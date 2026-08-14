import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from models.schemas import UserRegister, UserLogin
from database import get_supabase_client
from dependencies.auth import get_current_user_context, UserAuthContext
from dependencies.rate_limiter import limiter

logger = logging.getLogger("SHADOW")
router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register")
@limiter.limit("5/minute")
async def register(request: Request, user: UserRegister):
    try:
        client = get_supabase_client()
        response = client.auth.sign_up({
            "email": user.email,
            "password": user.password
        })
        return {"message": "Registration successful", "user": response.user.email}
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=400, detail="Registration failed. Please check your details and try again.")

@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, user: UserLogin):
    try:
        client = get_supabase_client()
        response = client.auth.sign_in_with_password({
            "email": user.email,
            "password": user.password
        })
        return {
            "access_token": response.session.access_token,
            "user": response.user.email
        }
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=401, detail="Invalid credentials")

@router.post("/logout")
async def logout(user_ctx: UserAuthContext = Depends(get_current_user_context)):
    try:
        if user_ctx.access_token:
            client = get_supabase_client(user_ctx.access_token)
            client.auth.admin.sign_out(user_ctx.access_token, scope="global")
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=400, detail="Logout failed. Please try again.")
