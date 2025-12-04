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

router = APIRouter(prefix="/admin", tags=["profesori"])

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
        SELECT Admin, Password, Email, Name FROM profesori WHERE Email = :u LIMIT 1;
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
        SELECT Email, Name, ID, Admin FROM profesori
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

class Profesor(BaseModel):
    nume: str = Field(..., min_length=2, max_length=255)
    email: EmailStr | None = None
    password: str = Field(..., min_length=6, max_length=255)
    admin: int

class EditProfesor(BaseModel):
    nume: str = Field(..., min_length=2, max_length=255)
    email: EmailStr | None = None
    admin: int


class ProfesorOut(BaseModel):
    ID: int
    Name: str
    Email: EmailStr | None
    admin: int

class ProfesorPassword(BaseModel):
    password: str = Field(..., min_length=6, max_length=255)    
    
@router.put("/changepassword/{profesor_id}", response_model=ProfesorOut)
async def update_profesor(
    profesor_id: int,
    body: ProfesorPassword,
    payload: dict = Depends(verify_jwt_token),
):
    """
    Reset the password of the admins.
    """

    params = {
        "id": profesor_id,
        "password": body.password
    }

    set_parts = ["Password = :password"]

    update_q = text(f"""
        UPDATE profesori
        SET {", ".join(set_parts)}
        WHERE ID = :id
    """)

    select_q = text("""
        SELECT ID, Name, Email
        FROM profesori
        WHERE ID = :id
    """)

    try:
        async with engine.begin() as conn:
            res = await conn.execute(update_q, params)
            if res.rowcount == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Profesor negasit",
                )

            row = (await conn.execute(select_q, {"id": profesor_id})).mappings().first()
    except exec.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Update violates password constraint.",
        )

    if not row:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated record.")

    return ProfesorOut(**row)

@router.put("/profesori/{profesor_id}", response_model=ProfesorOut)
async def update_profesor(
    profesor_id: int,
    body: EditProfesor,
    payload: dict = Depends(verify_jwt_token),
):
    """
    Full update of a profesor.
    """

    params = {
        "id": profesor_id,
        "nume": body.nume,
        "email": body.email,
        "admin": body.admin
        
    }

    set_parts = ["Name = :nume", "Email = :email", "Admin = :admin"]

    update_q = text(f"""
        UPDATE profesori
        SET {", ".join(set_parts)}
        WHERE ID = :id
    """)

    select_q = text("""
        SELECT ID, Name, Email, Admin
        FROM profesori
        WHERE ID = :id
    """)

    try:
        async with engine.begin() as conn:
            res = await conn.execute(update_q, params)
            if res.rowcount == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Profesor negasit",
                )

            row = (await conn.execute(select_q, {"id": profesor_id})).mappings().first()
    except exec.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Update violates a unique constraint (probably email).",
        )

    if not row:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated record.")

    return ProfesorOut(**row)

@router.delete("/profesori/{profesor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profesor(
    profesor_id: int,
    payload: dict = Depends(verify_jwt_token),
):
    """
    Permanently deletes a profesor by ID.
    Returns 204 No Content on success.
    """

    delete_q = text("DELETE FROM profesori WHERE ID = :id")

    try:
        async with engine.begin() as conn:
            res = await conn.execute(delete_q, {"id": profesor_id})
            if res.rowcount == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Profesor not found",
                )
    except exec.IntegrityError:
        # e.g. if there are foreign keys referencing this profesor
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Profesor cannot be deleted due to related records.",
        )

@router.post("/profesori", response_model=ProfesorOut, status_code=status.HTTP_201_CREATED)
async def add_profesor(
    body: Profesor,
    payload: dict = Depends(verify_jwt_token),  # token required
):
    """
    Adaugă un nou profesor în baza de date.
    Necesită un token JWT valid în antetul Authorization.
    """
    hashed_pw = pwd_context.hash(body.password)
    insert_q = text("""
        INSERT INTO profesori (Name, Email, Password, Admin)
        VALUES (:nume, :email, :password, :admin)
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
                    "admin": body.admin
                    
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
