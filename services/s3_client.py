import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from core.config import AppSettings

_settings = AppSettings()
_client = None


def get_s3_client():
    global _client
    if _client is not None:
        return _client

    kwargs = {}
    kwargs["config"] = Config(signature_version="s3v4", s3={"addressing_style": "virtual"})
    if _settings.region:
        kwargs["region_name"] = _settings.region
    if _settings.accesskey and _settings.secretkey:
        kwargs["aws_access_key_id"] = _settings.accesskey
        kwargs["aws_secret_access_key"] = _settings.secretkey
    if _settings.session_token:
        kwargs["aws_session_token"] = _settings.session_token

    _client = boto3.client("s3", **kwargs)
    return _client


def vehicle_s3_key(filename: str) -> str:
    name = (filename or "").strip().lstrip("/")
    if not name:
        return ""
    return f"vehicle/{name}"


def _object_exists(bucket: str, key: str) -> bool:
    if not bucket or not key:
        return False
    client = get_s3_client()
    try:
        client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        code = str(e.response.get("Error", {}).get("Code", "")).strip()
        if code in {"404", "NoSuchKey", "NotFound"}:
            return False
        return False


def resolve_vehicle_object_key(filename: str) -> str:
    bucket = (_settings.bucket_name or "").strip()
    if not bucket:
        return ""
    name = (filename or "").strip().lstrip("/")
    if not name:
        return ""
    candidates = [
        f"vehicle/{name}",
        f"Vehicle/{name}",
    ]
    for key in candidates:
        if _object_exists(bucket, key):
            return key
    return ""


def resolve_passcard_document_object_key(document_name: str, filename: str) -> str:  # added: resolve S3 key for passcard document folders (ex: d_or/{FileName})
    bucket = (_settings.bucket_name or "").strip()  # added: normalize bucket name
    if not bucket:  # added: no bucket configured
        return ""  # added: return empty key
    doc = (document_name or "").strip().strip("/")  # added: normalize doc folder input
    if not doc:  # added: missing folder
        return ""  # added: return empty key
    name = (filename or "").strip().lstrip("/")  # added: normalize filename
    if not name:  # added: missing filename
        return ""  # added: return empty key
    doc_lower = doc.lower()  # added: normalized lowercase folder
    doc_upper = doc.upper()  # added: normalized uppercase folder
    candidates = [  # added: possible object key candidates (case-variant folders)
        f"{doc_lower}/{name}",  # added: standard lowercase folder
        f"{doc_upper}/{name}",  # added: fallback uppercase folder
        f"{doc}/{name}",  # added: as-provided folder (in case it's mixed-case)
    ]  # added: end candidates
    for key in candidates:  # added: iterate through candidates
        if _object_exists(bucket, key):  # added: check object existence via HEAD
            return key  # added: return first match
    return ""  # added: not found


def presign_get_object(object_key: str, expires_seconds: int = 300) -> str:
    key = (object_key or "").strip().lstrip("/")
    if not key:
        return ""
    if not _settings.bucket_name:
        return ""
    client = get_s3_client()
    lower = key.lower()
    content_type = None
    if lower.endswith(".jpg") or lower.endswith(".jpeg"):
        content_type = "image/jpeg"
    elif lower.endswith(".png"):
        content_type = "image/png"
    elif lower.endswith(".webp"):
        content_type = "image/webp"
    params = {"Bucket": _settings.bucket_name, "Key": key}
    if content_type:
        params["ResponseContentType"] = content_type
    return client.generate_presigned_url(
        ClientMethod="get_object",
        Params=params,
        ExpiresIn=int(expires_seconds),
    )
