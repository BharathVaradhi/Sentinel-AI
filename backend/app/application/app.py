from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/login")
async def login(request: Request):
    body = await request.body()
    data = body.decode("utf-8")

    print(f"[Protected App] Received: {data}")

    return {
        "status": "success",
        "message": f"Login request processed: {data}"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)
