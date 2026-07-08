from app.config.redis_config import redis_client

CACHE_EXPIRY = 300  # 5 minutes


def is_cached(fingerprint: str) -> bool:
    return redis_client.exists(fingerprint) == 1


def add_to_cache(fingerprint: str):
    redis_client.setex(
        fingerprint,
        CACHE_EXPIRY,
        "SAFE"
    )
