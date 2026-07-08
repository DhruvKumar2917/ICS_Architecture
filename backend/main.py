"""
ICS AASG Backend - FastAPI Application Entry Point.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables from .env file immediately at startup
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

BACKEND_HOST = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", os.getenv("PORT", "7429")))

# Automatically clean the uploads directory on server startup
def clean_uploads_directory():
    uploads_dir = Path("uploads")
    if uploads_dir.exists():
        print("[startup] Cleaning uploads directory...", flush=True)
        for file_path in uploads_dir.iterdir():
            if file_path.is_file():
                try:
                    file_path.unlink()
                except Exception as e:
                    print(f"[startup] Failed to delete {file_path}: {e}", flush=True)

clean_uploads_directory()

from app.api.routes import api_router

app = FastAPI(title="ICS AASG — Authorization Attack Surface Graph API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/")
def home():
    return {"status": "ICS AASG backend running", "version": "2.0"}

@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=BACKEND_HOST,
        port=BACKEND_PORT,
        reload=True,
    )
