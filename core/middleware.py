import time
from fastapi import Request
from loguru import logger

async def log_request(request: Request, call_next):
    start_time = time.time()

    logger.info(f"Incoming Request: {request.method} {request.url.path} | "
                f"Query: {dict(request.query_params)} | "
                f"Client: {request.client.host if request.client else 'Unknown'}"
    )

    response = await call_next(request)

    duration = (time.time() - start_time) * 1000

    logger.info(
        f"Outgoing Response: {request.method} {request.url.path} {response.status_code} {duration}ms"
    )

    return response