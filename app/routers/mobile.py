from fastapi import APIRouter, Depends
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from fastapi import APIRouter, HTTPException, status, Depends, Header
from ..core.security import make_bearer_verifier
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
from sqlalchemy.exc import IntegrityError
import jwt
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
router = APIRouter(prefix="/mobile", tags=["mobile"])

verify_mobile = make_bearer_verifier(settings.API_TOKEN_MOBILE)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = "HS256"

class Enrollment(BaseModel):
    codmatricol: str


@router.get("/status", dependencies=[Depends(verify_mobile)])
async def mobile_status():
    return {"client": "mobile", "status": "ok"}



@router.post("/enroll")
async def admin_enroll(body: Enrollment):
    """
    Inscriere in aplicatie cu ajutor codului matricol
    """
    q = text("""
    SELECT ID, Token, Email, Name, Activ
    FROM elevi
    WHERE CodMatricol = :u
    LIMIT 1;
""")

    async with engine.connect() as conn:
        res = await conn.execute(q, {"u": body.codmatricol})
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    
    try:
        if row["ID"]>0:
            ok = True
        else:
            ok = False
        
    except Exception:
        ok = False

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    try:
        if row["Token"] is None:
            ok = True
        else:
            ok = False
        
    except Exception:
        ok = False

    if not ok:
        raise HTTPException(status_code=409, detail="User already enrolled")

    # Create a temporary JWT token (1 year)
    payload = {
        "CodMatricol": body.codmatricol,
        "iat": int(time.time()),
        "exp": int(time.time()) + 31536000,  # 1 year expiration
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    params = {
        "token": token,
        "dataactivare": datetime.now(),
        "activ": 1,
        "id": row["ID"]

        
    }

    set_parts = ["Token = :token", "DataActivare = :dataactivare", "Activ = :activ"]

    update_q = text(f"""
        UPDATE elevi
        SET {", ".join(set_parts)}
        WHERE ID = :id
    """)
    try:
        async with engine.begin() as conn:
            res = await conn.execute(update_q, params)
            if res.rowcount == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Elev negasit",
                )

    except exec.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Update violates a unique constraint (probably codmatricol).",
        )

    return {
        
        "codmatricol": body.codmatricol,
        "access_token": token,
        "token_type": "bearer",
        "name": row["Name"],
        "expires_in": 31536000
    }

http_bearer_scheme = HTTPBearer()

# --- TOKEN VERIFIER ---
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

