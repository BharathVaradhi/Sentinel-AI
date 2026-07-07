from fastapi import FastAPI, Request, HTTPException

from app.parser.parser import parse_request
from app.cache.fingerprint import generate_fingerprint
from app.cache.cache_manager import is_cached, add_to_cache
from app.forwarder.forwarder import forward_request

from security.rules.rule_engine import inspect
from app.decision.decision_engine import evaluate

app = FastAPI()


@app.post("/login")
async def login(request: Request):

    # Parse Request
    request_data = await parse_request(request)

    # Generate Fingerprint
    fingerprint = generate_fingerprint(request_data)

    # Cache Check
    if is_cached(fingerprint):
        print("\n[CACHE HIT] Request already verified.\n")

        return {
            "message": "Request Allowed (Cache Hit)"
        }

    print("\n[CACHE MISS] New request.\n")

    # Rule Engine
    rule_result = inspect(request_data)

    print("\n========== RULE ENGINE ==========")
    print(f"Matched     : {rule_result.matched}")
    print(f"Attack Type : {rule_result.attack_type}")
    print(f"Severity    : {rule_result.severity}")
    print(f"Rule ID     : {rule_result.rule_id}")
    print(f"Message     : {rule_result.message}")
    print("=================================\n")

    # Decision Engine
    decision = evaluate(rule_result)

    if not decision.allow:
        print("\n🚨 REQUEST BLOCKED 🚨\n")

        raise HTTPException(
            status_code=decision.status_code,
            detail=decision.message
        )

    print("\n✅ REQUEST ALLOWED\n")

    # Cache only safe requests
    add_to_cache(fingerprint)

    body = await request.body()

    return await forward_request(
      body=body,
      headers=request.headers
    ) 


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
