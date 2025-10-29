from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

def make_bearer_verifier(expected_token: str):
    """
    Returnează un dependency care validează Authorization: Bearer <token>.
    """
    security = HTTPBearer(auto_error=False)

    async def verify(credentials: HTTPAuthorizationCredentials = Depends(security)):
        if (
            credentials is None
            or credentials.scheme.lower() != "bearer"
            or credentials.credentials != expected_token
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    return verify