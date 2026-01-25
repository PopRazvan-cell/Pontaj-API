from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, status, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from ..core.security import make_bearer_verifier
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
import jwt
import time

router = APIRouter(prefix="/admin", tags=["elevi"])

# bcrypt password hashing/verification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = "HS256"

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
@router.get("/elevi")
async def get_all_students(payload: dict = Depends(verify_jwt_token), name: str = None):
    """
    Returnează toți utilizatorii admin cu informații complete (excluzând password_hash).
    Necesită un token JWT valid în antetul Authorization.
    """
    query = "SELECT Email, Name, ID, CodMatricol, Activ, DataActivare FROM elevi"

    params={}

    if name: 
        query+=" WHERE Name LIKE :name"
        params["name"]=f"%{name}%"

    query+=" ORDER BY Name;"


    q=text(query)

    async with engine.connect() as conn:
        res = await conn.execute(q, params)
        elevi = [dict(row._mapping) for row in res.fetchall()]

    return {
        "requested_by": payload["sub"],
        "count": len(elevi),
        "elevi": elevi
    }

verify_elevi = make_bearer_verifier(settings.API_TOKEN_ADMIN)

class Elev(BaseModel):
    nume: str = Field(..., min_length=2, max_length=255)
    email: EmailStr | None = None
    codmatricol: str = Field(..., min_length=4, max_length=8)
    activ: int
    

class ElevOut(BaseModel):
    ID: int
    Name: str = Field(..., min_length=2, max_length=255)
    Email: EmailStr | None = None
    CodMatricol: str = Field(..., min_length=4, max_length=8)
    Activ: int
    dataactivare: Optional[str] = Field(alias="DataActivare", default=None)
    

@router.put("/elevi/{elev_id}", response_model=ElevOut)
async def update_elevi(
    elev_id: int,
    body: Elev,
    payload: dict = Depends(verify_jwt_token),
):
    """
    Full update of a student.
    """

    params = {
        "id": elev_id,
        "nume": body.nume,
        "email": body.email,
        "codmatricol": body.codmatricol,
        "activ": body.activ,
        
    }

    set_parts = ["Name = :nume", "Email = :email", "CodMatricol = :codmatricol", "Activ = :activ"]

    update_q = text(f"""
        UPDATE elevi
        SET {", ".join(set_parts)}
        WHERE ID = :id
    """)

    select_q = text("""
        SELECT ID, Name, Email, CodMatricol, Activ
        FROM elevi
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

            row = (await conn.execute(select_q, {"id": elev_id})).mappings().first()
    except exec.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Update violates a unique constraint (probably email).",
        )

    if not row:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated record.")

    return ElevOut(**row)

@router.delete("/elevi/{elevi_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_elevi(
    elevi_id: int,
    payload: dict = Depends(verify_jwt_token),
):
    """
    Permanently deletes a student by ID.
    Returns 204 No Content on success.
    """

    delete_q = text("DELETE FROM elevi WHERE ID = :id")

    try:
        async with engine.begin() as conn:
            res = await conn.execute(delete_q, {"id": elevi_id})
            if res.rowcount == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Student not found",
                )
    except exec.IntegrityError:
        # e.g. if there are foreign keys referencing this profesor
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Student cannot be deleted due to related records.",
        )

@router.post("/elevi", response_model=ElevOut, status_code=status.HTTP_201_CREATED)
async def add_elev(
    body: Elev,
    payload: dict = Depends(verify_jwt_token),  # token required
):
    """
    Adaugă un nou elev în baza de date.
    Necesită un token JWT valid în antetul Authorization.
    """
    
    insert_q = text("""
        INSERT INTO elevi (Name, Email, CodMatricol, Activ)
        VALUES (:nume, :email, :codmatricol, :activ)
    """)

    select_q = text("""
        SELECT ID, Name, Email, CodMatricol, Activ, DataActivare
        FROM elevi
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
                    "codmatricol": body.codmatricol,
                    "activ": body.activ
                    
                    
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
            detail="Elevul există deja sau încalcă o constrângere.",
        )

    if not row:
        raise HTTPException(status_code=500, detail="Eșec la preluarea înregistrării create.")

    return ElevOut(**row)


@router.get("/scans_by_date")
async def get_scans(payload: dict = Depends(verify_jwt_token),
    start: datetime = Query(..., description="Start datetime (ISO 8601)"),
    end: datetime = Query(..., description="End datetime (ISO 8601)")
):
    """
    Returnează toate scanările dintr-o perioadă de timp.
    """

    if start >= end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Start date must be before end date"
        )

    q = text("""
        SELECT 
            s.id_elev,
            s.scan_time,
            s.token,
            e.name
        FROM scanari s
        JOIN elevi e ON e.id = s.id_elev
        WHERE s.scan_time BETWEEN :start AND :end
        ORDER BY s.scan_time ASC;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(
            q,
            {
                "start": start,
                "end": end
            }
        )
        scans = [dict(row._mapping) for row in res.fetchall()]

    return {
        "count": len(scans),
        "start": start,
        "end": end,
        "data": scans
    }

@router.get("/elevi_enrolled")
async def get_all_enrolled_students(payload: dict = Depends(verify_jwt_token)):
    """
    Returnează toți elevii enrolled cu informații complete (excluzând password_hash).
    Necesită un token JWT valid în antetul Authorization.
    """
    query = "SELECT Email, Name, ID, CodMatricol, Activ, DataActivare FROM elevi"
    query+=" WHERE Token IS NOT NULL"
    query+=" ORDER BY Name;"


    q=text(query)

    async with engine.connect() as conn:
        res = await conn.execute(q)
        elevi = [dict(row._mapping) for row in res.fetchall()]

    return {
        "requested_by": payload["sub"],
        "count": len(elevi),
        "elevi": elevi
    }
