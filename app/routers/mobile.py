from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import text
from ..db import engine
from ..core.config import settings
from fastapi import APIRouter, HTTPException, status, Depends, Header
from ..core.security import make_bearer_verifier
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
from sqlalchemy.exc import IntegrityError
import base64
import io
import qrcode
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

@router.get("/scans")
async def get_scans(payload: dict = Depends(verify_jwt_token),
    start: datetime = Query(..., description="Start datetime (ISO 8601)"),
    end: datetime = Query(..., description="End datetime (ISO 8601)")
):
    """
    Returnează toate scanările dintr-o perioadă de timp.
    """
    codmatricol = payload["CodMatricol"]
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
        WHERE e.CodMatricol=:codmatricol s.scan_time BETWEEN :start AND :end
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

@router.get("/verifyToken")
async def verifyToken(payload: dict = Depends(verify_jwt_token), creds: HTTPAuthorizationCredentials = Depends(http_bearer_scheme)):
    """
    Returnează daca token valabil si elevul activ.
    """
    codmatricol = payload["CodMatricol"]
   

    q = text("""
        SELECT Name, Activ  FROM elevi WHERE CodMatricol = :cm AND Token = :tk LIMIT 1;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(q,  {"cm": codmatricol, "tk": creds.credentials })
        elevi = [dict(row._mapping) for row in res.fetchall()]

    return {
        "Activ": elevi[0]["Activ"],
        "Name": elevi[0]["Name"]
    }

verify_elevi = make_bearer_verifier(settings.API_TOKEN_ADMIN)

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
    


@router.post("/qr", summary="Generate QR with short-lived JWT containing a DB value")
async def generate_qr_with_db_value(
    payload: dict = Depends(verify_jwt_token),
    creds: HTTPAuthorizationCredentials = Depends(http_bearer_scheme),
):
    """
    Uses the user's enroll token (Authorization: Bearer <token>) to fetch a DB value,
    then generates a 10-second JWT and returns it as a QR code (base64 PNG).
    """

    user_token = creds.credentials  # the enroll token

   
    q = text("""
        SELECT ID
        FROM elevi
        WHERE Token = :tk
        LIMIT 1;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(q, {"tk": user_token})
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid token or user not found")

    db_value = row["ID"]

    # ✅ Create short-lived JWT (10 seconds)
    now = int(time.time())
    qr_payload = {
        "value": db_value,
        "iat": now,
        "exp": now + 30,
    }

    qr_token = jwt.encode(qr_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # ✅ Create QR image from token
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "expires_in": 30,
        "token": qr_token,
        "qr_png_base64": png_b64,
        "exp": qr_payload["exp"],
    }

@router.post(
    "/qr_image",
    summary="Generate QR with short-lived JWT containing a DB value",
    response_class=Response,
)
async def generate_qr_with_db_value(
    payload: dict = Depends(verify_jwt_token),
    creds: HTTPAuthorizationCredentials = Depends(http_bearer_scheme),
):
    """
    Uses the user's enroll token (Authorization: Bearer <token>) to fetch a DB value,
    then generates a 10-second JWT and returns it as a PNG QR code.
    """

    user_token = creds.credentials  # enroll JWT

    # Fetch value from DB using enroll token
    q = text("""
        SELECT ID
        FROM elevi
        WHERE Token = :tk
        LIMIT 1;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(q, {"tk": user_token})
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid token or user not found")

    db_value = row["ID"]

    # Create short-lived JWT (10 seconds)
    now = int(time.time())
    qr_payload = {
        "value": db_value,
        "iat": now,
        "exp": now + 30,
    }

    qr_token = jwt.encode(qr_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Generate QR image
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Convert to PNG bytes
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    return Response(
        content=png_bytes,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store",
        },
    )

@router.get("/enrolled_student_scans")
async def get_scans(
    payload: dict = Depends(verify_jwt_token),
    start: datetime = Query(..., description="Start datetime (ISO 8601)"),
    end: datetime = Query(..., description="End datetime (ISO 8601)")
):
    """
    Returnează scanările elevului autentificat într-o perioadă de timp.
    """

    if start >= end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Start date must be before end date"
        )

    # student identity comes ONLY from the JWT
    id_elev = payload["id_elev"]

    q = text("""
        SELECT 
            s.scan_time,
            s.token,
            e.name
        FROM scanari s
        JOIN elevi e ON e.id = s.id_elev
        WHERE s.id_elev = :id_elev
          AND s.scan_time BETWEEN :start AND :end
        ORDER BY s.scan_time ASC;
    """)

    async with engine.connect() as conn:
        res = await conn.execute(
            q,
            {
                "id_elev": id_elev,
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

