from fastapi import APIRouter, Depends
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from ..core.security import make_bearer_verifier

router = APIRouter(prefix="/frontend", tags=["frontend"])

verify_frontend = make_bearer_verifier(settings.API_TOKEN_FRONTEND)

@router.get("/status", dependencies=[Depends(verify_frontend)])
async def frontend_status():
    return {"client": "frontend", "status": "ok"}

@router.get("/items", dependencies=[Depends(verify_frontend)])
async def frontend_items():
    async with engine.connect() as conn:
        r = await conn.execute(text("SELECT 42 as val"))
    return {"items": [{"val": r.one().val}]}