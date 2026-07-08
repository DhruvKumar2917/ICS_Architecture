from fastapi import APIRouter
from app.api.upload import router as upload_router
from app.api.analysis import router as analysis_router

api_router = APIRouter()

api_router.include_router(upload_router)
api_router.include_router(analysis_router)
