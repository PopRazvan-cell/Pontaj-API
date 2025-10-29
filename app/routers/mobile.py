from fastapi import APIRouter, Depends
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from ..core.security import make_bearer_verifier

router = APIRouter(prefix="/mobile", tags=["mobile"])

verify_mobile = make_bearer_verifier(settings.API_TOKEN_MOBILE)

@router.get("/status", dependencies=[Depends(verify_mobile)])
async def mobile_status():
    return {"client": "mobile", "status": "ok"}

@router.get("/profile", dependencies=[Depends(verify_mobile)])
async def mobile_profile():
    async with engine.connect() as conn:
        r = await conn.execute(text("SELECT 'john.doe' as username"))
    return {"username": r.one().username}