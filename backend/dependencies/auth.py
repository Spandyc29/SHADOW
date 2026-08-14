import logging
from dataclasses import dataclass
from typing import Optional
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase_auth.errors import AuthApiError
from database import supabase, get_supabase_client
from supabase import Client

logger = logging.getLogger("SHADOW")

security = HTTPBearer(auto_error=False)

@dataclass
class UserAuthContext:
    user_id: str
    access_token: Optional[str]
    is_guest: bool = False

    def get_client(self) -> Client:
        return get_supabase_client(self.access_token)

async def get_current_user_context(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> UserAuthContext:
    """
    Extracts and validates the Supabase JWT token from the Authorization header.
    Returns UserAuthContext with user_id and access_token.
    Raises 401 HTTP_UNAUTHORIZED if missing or invalid.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    try:
        client = get_supabase_client(token)
        user_response = client.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return UserAuthContext(
            user_id=str(user_response.user.id),
            access_token=token,
            is_guest=False
        )
    except AuthApiError as e:
        logger.warning(f"[SHADOW Auth] JWT verification failed: {e.message}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired authentication token: {e.message}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SHADOW Auth] Unexpected error during token verification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user_id(
    ctx: UserAuthContext = Depends(get_current_user_context)
) -> str:
    return ctx.user_id

async def get_current_user_context_or_guest(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_guest_mode: Optional[str] = Header(None)
) -> UserAuthContext:
    if credentials and credentials.credentials:
        return await get_current_user_context(credentials)
    
    if x_guest_mode and x_guest_mode.lower() == "true":
        return UserAuthContext(
            user_id="guest",
            access_token=None,
            is_guest=True
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication credentials missing.",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_current_user_id_or_guest(
    ctx: UserAuthContext = Depends(get_current_user_context_or_guest)
) -> str:
    return ctx.user_id
