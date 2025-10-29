from fastapi import APIRouter, Depends
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from ..core.security import make_bearer_verifier

router = APIRouter(prefix="/admin", tags=["admin"])

verify_admin = make_bearer_verifier(settings.API_TOKEN_ADMIN)

@router.get("/status", dependencies=[Depends(verify_admin)])
async def admin_status():
    return {"client": "admin", "status": "ok"}

@router.get("/metrics", dependencies=[Depends(verify_admin)])
async def admin_metrics():
    async with engine.connect() as conn:
        r = await conn.execute(text("SELECT 1 as up"))
    return {"db_up": r.one().up == 1}