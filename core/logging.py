from loguru import logger
import sys

def setup_logging(debug: bool):
    logger.remove()

    logger.add(sys.stdout,
                level="DEBUG" if debug else "INFO",
                format="{time} | {level} | {message}")

    return logger