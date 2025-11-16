from fastapi import APIRouter, HTTPException, status, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from ..core.security import make_bearer_verifier
from passlib.context import CryptContext
from pydantic import BaseModel
import jwt
import time

router = APIRouter(prefix="/admin", tags=["admin"])

# bcrypt password hashing/verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = "HS256"

class LoginRequest(BaseModel):
    username: str
    password: str

# --- LOGIN ENDPOINT ---
@router.post("/login")
async def admin_login(body: LoginRequest):
    """
    Login endpoint:
    - Validates admin username/password from MySQL
    - Returns a JWT token and username
    """
    q = text("""
        SELECT Password, Email, Name FROM profesorii WHERE Email = :u LIMIT 1;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(q, {"u": body.username})
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    
    try:
        ok = pwd_context.verify(body.password, row["Password"])
    except Exception:
        ok = False

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create a temporary JWT token (1 hour)
    payload = {
        "sub": row["Email"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # 1 hour expiration
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {
        "username": row["Email"],
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 3600
    }

http_bearer_scheme = HTTPBearer()

# --- TOKEN VERIFIER ---
def verify_jwt_token(creds: HTTPAuthorizationCredentials = Depends(http_bearer_scheme)):
    """
    Extract and verify the JWT token using the HTTPBearer scheme.
    'creds.credentials' will contain the raw token string.
    'creds.scheme' will be "Bearer".
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

# --- PROTECTED ROUTE ---
@router.get("/profesori")
async def get_all_admins(payload: dict = Depends(verify_jwt_token)):
    """
    Returns all admin users with full info (excluding password_hash).
    Requires a valid JWT token in Authorization header.
    """
    q = text("""
        SELECT Email, Name FROM profesorii
        ORDER BY Name;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(q)
        admins = [dict(row._mapping) for row in res.fetchall()]

    return {
        "requested_by": payload["sub"],
        "count": len(admins),
        "admins": admins
    }

verify_admin = make_bearer_verifier(settings.API_TOKEN_ADMIN)

@router.get("/status", dependencies=[Depends(verify_admin)])
async def admin_status():
    return {"client": "admin", "status": "ok"}

@router.get("/metrics", dependencies=[Depends(verify_admin)])
async def admin_metrics():
    async with engine.connect() as conn:
        r = await conn.execute(text("SELECT 1 as up"))
    return {"db_up": r.one().up == 1}
