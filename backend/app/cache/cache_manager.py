cache_store = {}


def is_cached(fingerprint: str) -> bool:
    return fingerprint in cache_store


def add_to_cache(fingerprint: str):
    cache_store[fingerprint] = True
