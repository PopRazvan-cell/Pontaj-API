from fastapi import APIRouter, HTTPException, status, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from ..core.security import make_bearer_verifier
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
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
    Punct final de autentificare:
    -Validează numele de utilizator/parola admin din MySQL
    -Returnează un token JWT și numele de utilizator
    """
    q = text("""
        SELECT Password, Email, Name FROM profesori WHERE Email = :u LIMIT 1;
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

# --- PROTECTED ROUTE ---
@router.get("/profesori")
async def get_all_admins(payload: dict = Depends(verify_jwt_token)):
    """
    Returnează toți utilizatorii admin cu informații complete (excluzând password_hash).
    Necesită un token JWT valid în antetul Authorization.
    """
    q = text("""
        SELECT Email, Name FROM profesori
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

class ProfesorCreate(BaseModel):
    nume: str = Field(..., min_length=2, max_length=255)
    email: EmailStr | None = None
    password: str = Field(..., min_length=6, max_length=255)
    


class ProfesorOut(BaseModel):
    ID: int
    Name: str
    Email: EmailStr | None
    


@router.post("/profesori", response_model=ProfesorOut, status_code=status.HTTP_201_CREATED)
async def add_profesor(
    body: ProfesorCreate,
    payload: dict = Depends(verify_jwt_token),  # token required
):
    """
    Adaugă un nou profesor în baza de date.
    Necesită un token JWT valid în antetul Authorization.
    """
    hashed_pw = pwd_context.hash(body.password)
    insert_q = text("""
        INSERT INTO profesori (Name, Email, Password)
        VALUES (:nume, :email, :password)
    """)

    select_q = text("""
        SELECT ID, Name, Email
        FROM profesori
        WHERE ID = :id
    """)

    try:
        async with engine.begin() as conn:
            # Insert profesor
            result = await conn.execute(
                insert_q,
                {
                    "nume": body.nume,
                    "email": body.email,
                    "password": hashed_pw,
                    
                },
            )
            # MySQL last insert id
            new_id = result.lastrowid or (
                await conn.execute(text("SELECT LAST_INSERT_ID() AS id"))
            ).mappings().first()["id"]

            # Fetch and return created row
            row = (
                await conn.execute(select_q, {"id": new_id})
            ).mappings().first()

    except exec.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Profesorul există deja sau încalcă o constrângere.",
        )

    if not row:
        raise HTTPException(status_code=500, detail="Eșec la preluarea înregistrării create.")

    return ProfesorOut(**row)
