
from fastapi import FastAPI, Request
from app.parser.parser import parse_request
from app.cache.fingerprint import generate_fingerprint
from app.cache.cache_manager import is_cached, add_to_cache
from security.rules.rule_engine import inspect

app = FastAPI()


@app.post("/login")
async def login(request: Request):

    request_data = await parse_request(request)
    fingerprint = generate_fingerprint(request_data)

    if is_cached(fingerprint):
     print("\n[CACHE HIT] Request already verified.\n")
    else:
     print("\n[CACHE MISS] New request.\n")
     add_to_cache(fingerprint)

     rule_result = inspect(request_data)

     print("\n========== RULE ENGINE ==========")
     print(f"Matched     : {rule_result.matched}")
     print(f"Attack Type : {rule_result.attack_type}")
     print(f"Severity    : {rule_result.severity}")
     print(f"Rule ID     : {rule_result.rule_id}")
     print(f"Message     : {rule_result.message}")
     print("=================================\n")

    return {
        "message": "Request Parsed Successfully"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
