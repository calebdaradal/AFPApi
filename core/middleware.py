import time
import json
from fastapi import Request
from fastapi.responses import Response, StreamingResponse
from loguru import logger

async def log_request(request: Request, call_next):
    start_time = time.time()

    # Log incoming request
    logger.info(f"Incoming Request: {request.method} {request.url.path} | "
                f"Query: {dict(request.query_params)} | "
                f"Client: {request.client.host if request.client else 'Unknown'}"
    )

    response = await call_next(request)

    duration = (time.time() - start_time) * 1000

    # Log response status and duration
    logger.info(
        f"Outgoing Response: {request.method} {request.url.path} | "
        f"Status: {response.status_code} | Duration: {duration:.2f}ms"
    )

    # Log response body for JSON responses
    # Only log if it's a JSON response and not a streaming response
    if not isinstance(response, StreamingResponse):
        # Try to read response body
        try:
            # Get response body
            response_body = b""
            async for chunk in response.body_iterator:
                response_body += chunk
            
            # Try to parse as JSON
            if response_body:
                try:
                    response_data = json.loads(response_body.decode())
                    # Log the response data (including tokens)
                    logger.info(f"Response Body: {json.dumps(response_data, indent=2)}")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # If not JSON, log as text (truncated if too long)
                    body_text = response_body.decode('utf-8', errors='ignore')
                    if len(body_text) > 500:
                        body_text = body_text[:500] + "... (truncated)"
                    logger.info(f"Response Body: {body_text}")
            
            # Recreate response with the body we read
            return Response(
                content=response_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type
            )
        except Exception as e:
            logger.warning(f"Could not log response body: {e}")
            return response
    
    return response