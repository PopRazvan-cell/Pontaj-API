from fastapi import FastAPI, HTTPException
import asyncio
from fastapi.middleware.cors import CORSMiddleware

from .db import lifespan, db_ping
from .routers import frontend, admin_profesori, mobile

app = FastAPI(title="Prod API – multi-client", lifespan=lifespan)
origins = [
    "http://localhost:3000",  # React dev
    "http://127.0.0.1:3000",
    "https://admin.pontaj.binarysquad.club",
    "https://api.pontaj.binarysquad.club"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,        # use ["*"] only if NOT using credentials
    allow_credentials=True,       # cookies/auth headers
    allow_methods=["*"],          # or list: ["GET","POST",...]
    allow_headers=["*"],          # or list specific headers
)
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