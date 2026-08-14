import asyncio
import functools
import hashlib
import inspect
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded


class ShadowLimiter(Limiter):
    """
    Subclass of SlowAPI Limiter that safely bypasses rate limiting
    when an endpoint function is invoked directly in Python unit tests
    passing Pydantic model objects instead of starlette.requests.Request.
    """

    def limit(self, *args, **kwargs):
        decorator = super().limit(*args, **kwargs)

        def custom_decorator(func):
            wrapped = decorator(func)
            sig = inspect.signature(func)
            idx = None
            for i, p in enumerate(sig.parameters.values()):
                if p.name == "request":
                    idx = i
                    break

            if inspect.iscoroutinefunction(func):
                @functools.wraps(func)
                async def safe_async_wrapper(*w_args, **w_kwargs):
                    if self.enabled:
                        req = w_kwargs.get(
                            "request",
                            w_args[idx] if idx is not None and idx < len(w_args) else None
                        )
                        if not isinstance(req, Request):
                            return await func(*w_args, **w_kwargs)
                    return await wrapped(*w_args, **w_kwargs)

                return safe_async_wrapper

            return wrapped

        return custom_decorator


def get_rate_limit_key(request: Request) -> str:
    """
    Determines the rate limit identity key:
    - Authenticated users: Keyed by token hash ('user:<sha256(token)>')
    - Guest users / unauthenticated: Keyed by client IP address ('ip:<client_ip>')
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            return f"user:{token_hash}"

    return f"ip:{get_remote_address(request)}"


limiter = ShadowLimiter(key_func=get_rate_limit_key)


def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """
    Custom exception handler for RateLimitExceeded.
    Returns HTTP 429 Too Many Requests with standard JSON format and Retry-After header.
    """
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please try again later."},
        headers={"Retry-After": "60"}
    )
