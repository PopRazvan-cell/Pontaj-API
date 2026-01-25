from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from ..core.security import make_bearer_verifier
from pydantic import BaseModel, EmailStr, Field
router = APIRouter(prefix="/frontend", tags=["frontend"])

verify_frontend = make_bearer_verifier(settings.API_TOKEN_FRONTEND)

class scan(BaseModel):
    ID: str

@router.get("/status", dependencies=[Depends(verify_frontend)])
async def frontend_status():
    return {"client": "frontend", "status": "ok"}

@router.get("/items", dependencies=[Depends(verify_frontend)])
async def frontend_items():
    async with engine.connect() as conn:
        r = await conn.execute(text("SELECT 42 as val"))
    return {"items": [{"val": r.one().val}]}


http_bearer_scheme = HTTPBearer()
JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = "HS256"
def verify_jwt_token(creds: HTTPAuthorizationCredentials = Depends(http_bearer_scheme)):
    """
    Extrage și verifică tokenul JWT folosind schema HTTPBearer.
    'creds.credentials' va conține șirul tokenului brut.
    'creds.scheme' va fi "Bearer".
    """
    # 1. Get the token directly from the 'creds' object
    token = creds.credentials 

    try:
        # 2. Decode the token. No need to check for "Bearer " or split the string.
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    

@router.post("/scan")
async def scan(payload: dict = Depends(verify_jwt_token), creds: HTTPAuthorizationCredentials = Depends(http_bearer_scheme)):
    """
    Returnează daca token valabil si elevul activ.
    """
    ID = payload["value"]
   

    q = text("""
        SELECT Name, Activ  FROM elevi WHERE ID = :id;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(q,  {"id": ID})
        elevi = [dict(row._mapping) for row in res.fetchall()]

    return {
        "Activ": elevi[0]["Activ"],
        "Name": elevi[0]["Name"]
    }