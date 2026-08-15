from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from dependencies.rate_limiter import limiter, custom_rate_limit_exceeded_handler
from routers import auth, files, scans, dashboard, hash, url, domain, ip, reports, shadow_ai, settings

import config

docs_url = "/docs" if config.ENABLE_DOCS else None
redoc_url = "/redoc" if config.ENABLE_DOCS else None
openapi_url = "/openapi.json" if config.ENABLE_DOCS else None

app = FastAPI(
    title="Shadow",
    version="1.0.0",
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    return response

allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://shadowcti.netlify.app",
]
if config.FRONTEND_URL and config.FRONTEND_URL not in allowed_origins:
    allowed_origins.append(config.FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth.router)
app.include_router(files.router)
app.include_router(scans.router)
app.include_router(dashboard.router)
app.include_router(hash.router)
app.include_router(url.router)
app.include_router(domain.router)
app.include_router(ip.router)
app.include_router(reports.router)
app.include_router(shadow_ai.router)
app.include_router(settings.router)

@app.get("/health")
def health():
    return {"status": "Shadow is running"}

