from fastapi import FastAPI, HTTPException
import asyncio

from .db import lifespan, db_ping
from .routers import frontend, admin_profesori, mobile

app = FastAPI(title="Prod API – multi-client", lifespan=lifespan)

# Endpoints publice (pentru orchestrare)
@app.get("/health/live")
async def liveness():
    return {"status": "alive"}

@app.get("/health/ready")
async def readiness():
    try:
        await db_ping(timeout_sec=2)
        return {"status": "ready", "dependencies": {"mysql": "ok"}}
    except Exception as e:
        raise HTTPException(status_code=503, detail={"mysql": "down", "error": str(e)})

# Montează routerele per client
app.include_router(frontend.router)
app.include_router(admin_profesori.router)
app.include_router(mobile.router)