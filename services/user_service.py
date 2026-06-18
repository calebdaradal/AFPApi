"""
User validation against MongoDB. Passwords stored as bcrypt hashes.
Uses bcrypt package directly (passlib incompatible with newer bcrypt).
"""
import bcrypt
import re  # added: enable case-insensitive email lookup for login
import hashlib  # added: support migrating legacy SHA-256 password hashes to bcrypt
from services.mongo_client import get_users_collection
from core.config import AppSettings  # added: allow enabling/disabling debug logs based on DEBUG env var
from loguru import logger  # added: detailed debug logging for login investigations

# Bcrypt only hashes first 72 bytes
_MAX_PASSWORD_BYTES = 72
_BCRYPT_PREFIX_RE = re.compile(r"^\$2[aby]\$")  # added: detect bcrypt hashes ($2a$, $2b$, $2y$)
_SHA256_HEX_RE = re.compile(r"^[a-fA-F0-9]{64}$")  # added: detect legacy SHA-256 hex digests
settings = AppSettings()  # added: load DEBUG flag from .env for conditional logging


def _to_bytes(s: str) -> bytes:
    """Encode password to bytes and truncate to bcrypt limit."""
    b = s.encode("utf-8")
    return b[:_MAX_PASSWORD_BYTES] if len(b) > _MAX_PASSWORD_BYTES else b


def hash_password(plain_password: str) -> str:
    """Hash a plain password for storing in DB."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(_to_bytes(plain_password), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check plain password against stored hash."""
    return bcrypt.checkpw(
        _to_bytes(plain_password),
        hashed_password.encode("utf-8"),
    )


def get_user_email(user: dict) -> str:  # added: support both old (email) and new (Email) Mongo schemas
    """Return user's email from either legacy or new schema."""  # added: docstring for helper
    return (user.get("email") or user.get("Email") or "").strip()  # added: handle both field names


def _get_stored_password_field_value(user: dict) -> str:  # added: support both password_hash and Security.Password
    """Return stored bcrypt hash from either legacy or new schema."""  # added: docstring for helper
    security = user.get("Security") if isinstance(user.get("Security"), dict) else {}  # added: safely read nested object
    raw = user.get("password_hash")  # changed: fetch legacy field without coercing types yet
    if raw is None:  # added: fallback to new schema field only when legacy is absent
        raw = security.get("Password")  # added: read new schema password field
    if raw is None:  # added: handle missing password value
        return ""  # changed: always return a string
    if isinstance(raw, bytes):  # added: support Mongo values stored as bytes
        return raw.decode("utf-8", errors="replace").strip()  # added: decode bytes then strip whitespace
    return str(raw).strip()  # changed: coerce non-string values to string safely


def _password_field_source(user: dict) -> str:  # added: help logs show which field is used for password
    security = user.get("Security") if isinstance(user.get("Security"), dict) else {}  # added: safely read nested object
    if user.get("password_hash") is not None:  # added: detect legacy password field presence
        return "password_hash"  # added: legacy schema source
    if security.get("Password") is not None:  # added: detect new schema password field presence
        return "Security.Password"  # added: new schema source
    return "missing"  # added: no password found


def _sha256_hex(plain_password: str) -> str:  # added: compute SHA-256 hex for legacy password verification
    return hashlib.sha256(plain_password.encode("utf-8")).hexdigest()  # added: deterministic hex digest (no truncation)


def _sha256_hex_with_encoding(value: str, encoding: str) -> str:  # added: support alternate encodings used by other stacks (e.g., UTF-16LE)
    return hashlib.sha256(value.encode(encoding)).hexdigest()  # added: deterministic hex digest for specified encoding


def _sha256_hex_candidates_for_user(password: str, user: dict) -> list:  # added: generate common legacy SHA-256 variants without exposing secrets
    email_val = get_user_email(user)  # added: use stored email as possible salt component
    tenant_id = (user.get("TenantId") or "").strip()  # added: use tenant id as possible salt component
    username = (user.get("UserName") or "").strip()  # added: use username as possible salt component
    pw = password or ""  # added: normalize password to string
    pw_trim = pw.strip()  # added: common client-side normalization
    email_lower = email_val.lower() if email_val else ""  # added: normalize email for salted variants
    pepper = settings.key or ""  # added: password pepper/key from .env KEY for new hashing structure
    pw_pep = pw + pepper  # added: {password}+{KEY} variant used by the new database hashing structure
    pw_trim_pep = pw_trim + pepper  # added: trimmed password then pepper (common normalization)
    items = [  # added: list of (label, digest) for comparison
        ("sha256_utf8_password", _sha256_hex_with_encoding(pw, "utf-8")),  # added: sha256(password) UTF-8
        ("sha256_utf8_password_trim", _sha256_hex_with_encoding(pw_trim, "utf-8")),  # added: sha256(trim(password)) UTF-8
        ("sha256_utf16le_password", _sha256_hex_with_encoding(pw, "utf-16le")),  # added: sha256(password) UTF-16LE (common in some .NET contexts)
        ("sha256_utf16le_password_trim", _sha256_hex_with_encoding(pw_trim, "utf-16le")),  # added: sha256(trim(password)) UTF-16LE
        ("sha256_utf8_password_plus_KEY", _sha256_hex_with_encoding(pw_pep, "utf-8")),  # added: sha256(password + KEY) UTF-8
        ("sha256_utf8_password_trim_plus_KEY", _sha256_hex_with_encoding(pw_trim_pep, "utf-8")),  # added: sha256(trim(password) + KEY) UTF-8
        ("sha256_utf16le_password_plus_KEY", _sha256_hex_with_encoding(pw_pep, "utf-16le")),  # added: sha256(password + KEY) UTF-16LE
        ("sha256_utf16le_password_trim_plus_KEY", _sha256_hex_with_encoding(pw_trim_pep, "utf-16le")),  # added: sha256(trim(password) + KEY) UTF-16LE
    ]  # added: end base variants
    if email_val:  # added: include email-salted variants when email exists
        items.extend([  # added: salted variants
            ("sha256_utf8_email_plus_password", _sha256_hex_with_encoding(email_val + pw, "utf-8")),  # added: sha256(email + password)
            ("sha256_utf8_password_plus_email", _sha256_hex_with_encoding(pw + email_val, "utf-8")),  # added: sha256(password + email)
            ("sha256_utf8_emailLower_plus_password", _sha256_hex_with_encoding(email_lower + pw, "utf-8")),  # added: sha256(lower(email) + password)
            ("sha256_utf8_password_plus_emailLower", _sha256_hex_with_encoding(pw + email_lower, "utf-8")),  # added: sha256(password + lower(email))
        ])  # added: end email-salted variants
    if tenant_id:  # added: include tenant-salted variants when tenant id exists
        items.extend([  # added: salted variants
            ("sha256_utf8_tenant_plus_password", _sha256_hex_with_encoding(tenant_id + pw, "utf-8")),  # added: sha256(tenantId + password)
            ("sha256_utf8_password_plus_tenant", _sha256_hex_with_encoding(pw + tenant_id, "utf-8")),  # added: sha256(password + tenantId)
        ])  # added: end tenant-salted variants
    if username:  # added: include username-salted variants when username exists
        items.extend([  # added: salted variants
            ("sha256_utf8_username_plus_password", _sha256_hex_with_encoding(username + pw, "utf-8")),  # added: sha256(userName + password)
            ("sha256_utf8_password_plus_username", _sha256_hex_with_encoding(pw + username, "utf-8")),  # added: sha256(password + userName)
        ])  # added: end username-salted variants
    return items  # added: return all candidates


def find_user_by_email_with_reason(users, raw_email: str):  # added: same lookup as find_user_by_email but also returns match reason
    email_raw = (raw_email or "").strip()  # added: normalize input to avoid whitespace mismatch
    if not email_raw:  # added: reject empty email
        return None, "empty_email"  # added: return a reason for logs
    user = users.find_one({"email": email_raw})  # added: try legacy exact match first
    if user:  # added: early return when found
        return user, "email_exact"  # added: report which query matched
    user = users.find_one({"Email": email_raw})  # added: try new schema exact match
    if user:  # added: early return when found
        return user, "Email_exact"  # added: report which query matched
    pattern = rf"^\s*{re.escape(email_raw)}\s*$"  # added: allow surrounding whitespace for case-insensitive match
    user = users.find_one({"email": {"$regex": pattern, "$options": "i"}})  # added: legacy field case-insensitive lookup
    if user:  # added: early return when found
        return user, "email_regex_i"  # added: report which query matched
    user = users.find_one({"Email": {"$regex": pattern, "$options": "i"}})  # added: new field case-insensitive lookup
    if user:  # added: early return when found
        return user, "Email_regex_i"  # added: report which query matched
    return None, "not_found"  # added: report that user did not exist


def find_user_by_email(users, raw_email: str):  # added: shared lookup for legacy and new Mongo schemas
    """Find a user by email across both `email` and `Email` fields (case-insensitive)."""  # added: docstring for helper
    user, _ = find_user_by_email_with_reason(users, raw_email)  # changed: delegate to the variant that returns a match reason
    return user  # changed: preserve original return type for existing callers


def find_user_by_email_value(raw_email: str):  # added: convenience wrapper used by other modules
    """Find a user document by email using the shared users collection."""  # added: docstring for helper
    return find_user_by_email(get_users_collection(), raw_email)  # added: reuse shared lookup logic



def validate_user(email: str, password: str) -> bool:
    """
    Check credentials against MongoDB users collection.
    Returns True only if user exists and password matches.
    """
    users = get_users_collection()  # added: read from configured MongoDB users collection
    user, match_reason = find_user_by_email_with_reason(users, email)  # changed: fetch user and match reason for comprehensive logs
    if not user:  # added: user not found
        if settings.debug:  # added: only emit detailed logs when DEBUG=True
            logger.warning(  # added: indicate why validation failed without leaking secrets
                "validate_user failed: user not found (email_input={!r}, match_reason={!r})",  # added: include safe context
                (email or "").strip(),  # added: log normalized email only
                match_reason,  # added: log which lookup path was attempted
            )  # added: end log call
        return False  # added: invalid credentials
    stored = _get_stored_password_field_value(user)  # added: read stored password hash from correct field
    if not stored:  # added: cannot validate if password is missing
        if settings.debug:  # added: only emit detailed logs when DEBUG=True
            logger.warning(  # added: indicate why validation failed without leaking secrets
                "validate_user failed: stored password missing (email_input={!r}, match_reason={!r}, user_id={!r})",  # added: include safe context
                (email or "").strip(),  # added: log normalized email only
                match_reason,  # added: which lookup matched
                str(user.get("_id")),  # added: log Mongo _id only
            )  # added: end log call
        return False  # added: invalid credentials
    is_bcrypt = bool(_BCRYPT_PREFIX_RE.match(stored))  # added: compute bcrypt detection once for logging
    if settings.debug:  # added: only emit detailed logs when DEBUG=True
        logger.info(  # added: high-signal login diagnostics (no password / no hash printed)
            "validate_user: user found (email_input={!r}, match_reason={!r}, user_id={!r}, password_source={!r}, stored_len={}, is_bcrypt={}, key_len={})",  # changed: include KEY length only (no value)
            (email or "").strip(),  # added: log normalized email only
            match_reason,  # added: which query matched
            str(user.get("_id")),  # added: log Mongo _id only
            _password_field_source(user),  # added: show which field held the password
            len(stored),  # added: show length only (no content)
            is_bcrypt,  # added: show whether bcrypt prefix was detected
            len(settings.key or ""),  # added: show whether KEY is present (length only)
        )  # added: end log call
    if is_bcrypt:  # changed: normal path for bcrypt stored hashes
        ok = verify_password(password, stored)  # changed: try bcrypt verification using raw password
        if not ok and (settings.key or ""):  # added: support bcrypt(password + KEY) storage
            ok = verify_password(password + (settings.key or ""), stored)  # added: try bcrypt verification using peppered password
        if settings.debug:  # added: only emit detailed logs when DEBUG=True
            logger.info(  # added: log bcrypt verification outcome without leaking secrets
                "validate_user bcrypt verify result: {} (user_id={!r})",  # added: include only boolean result
                ok,  # added: boolean verification result
                str(user.get("_id")),  # added: user id for correlation
            )  # added: end log call
        return ok  # changed: return the verification result
    if password == stored:  # added: legacy plaintext password migration path (upgrades to bcrypt on successful match)
        new_hash = hash_password(password)  # added: convert plaintext to bcrypt hash using required standard
        if "password_hash" in user:  # added: migrate legacy field location
            users.update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash}})  # added: store bcrypt hash in legacy field
        else:  # added: migrate to new schema field location
            users.update_one({"_id": user["_id"]}, {"$set": {"Security.Password": new_hash}})  # added: store bcrypt hash in new schema field
        if settings.debug:  # added: only emit detailed logs when DEBUG=True
            logger.warning(  # added: warn that plaintext password was detected and migrated
                "validate_user migrated plaintext password to bcrypt (user_id={!r}, password_source={!r})",  # added: no password printed
                str(user.get("_id")),  # added: user id for correlation
                _password_field_source(user),  # added: which field was updated
            )  # added: end log call
        return True  # added: allow login after migration
    if _SHA256_HEX_RE.match(stored):  # added: support legacy SHA-256 hex digest stored passwords
        stored_l = stored.lower()  # added: normalize stored hex for comparisons
        candidates = _sha256_hex_candidates_for_user(password, user)  # added: compute common legacy sha256 variants
        ok = False  # added: track if any candidate matches
        matched_label = None  # added: record which candidate matched for logs
        for label, digest in candidates:  # added: iterate through candidates
            if digest.lower() == stored_l:  # added: compare normalized hex
                ok = True  # added: mark match
                matched_label = label  # added: record matching scheme
                break  # added: stop at first match
        if settings.debug:  # added: only emit detailed logs when DEBUG=True
            logger.info(  # added: log SHA-256 verification outcome without leaking secrets
                "validate_user sha256 verify result: {} (user_id={!r}, password_source={!r}, matched_scheme={!r})",  # changed: include which scheme matched (still no secrets)
                ok,  # added: boolean verification result
                str(user.get("_id")),  # added: user id for correlation
                _password_field_source(user),  # added: which field held the password
                matched_label,  # added: which sha256 variant matched (or None)
            )  # added: end log call
        if ok:  # added: migrate sha256 to bcrypt on successful match
            new_hash = hash_password(password)  # added: upgrade to bcrypt for future logins
            if "password_hash" in user:  # added: migrate legacy field location
                users.update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash}})  # added: store bcrypt hash
            else:  # added: migrate to new schema field location
                users.update_one({"_id": user["_id"]}, {"$set": {"Security.Password": new_hash}})  # added: store bcrypt hash
            if settings.debug:  # added: only emit detailed logs when DEBUG=True
                logger.warning(  # added: warn that sha256 password was detected and migrated
                    "validate_user migrated sha256 password to bcrypt (user_id={!r}, password_source={!r})",  # added: safe context only
                    str(user.get("_id")),  # added: user id for correlation
                    _password_field_source(user),  # added: which field was updated
                )  # added: end log call
            return True  # added: allow login after migration
    if settings.debug:  # added: only emit detailed logs when DEBUG=True
        logger.warning(  # added: indicate password mismatch without leaking secrets
            "validate_user failed: password mismatch (email_input={!r}, match_reason={!r}, user_id={!r}, is_bcrypt={})",  # added: include safe metadata
            (email or "").strip(),  # added: log normalized email only
            match_reason,  # added: which query matched
            str(user.get("_id")),  # added: user id for correlation
            is_bcrypt,  # added: whether hash looked like bcrypt
        )  # added: end log call
    return False  # added: password mismatch
