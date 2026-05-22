from fastapi import FastAPI, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import uuid
import traceback

from parsers.text_parser import text_to_graph
from parsers.pdf_parser import extract_pdf_text
from parsers.table_parser import table_to_graph
from parsers.image_parser import image_to_graph

app = FastAPI(title="Architecture Diagram Generator API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


@app.get("/")
def home():
    return {"status": "Backend running"}


@app.get("/health")
def health():
    return {"status": "ok"}


def safe_text_to_graph(text: str):
    try:
        return text_to_graph(text)
    except Exception as e:
        traceback.print_exc()
        return {"nodes": [], "edges": [], "error": str(e)}


@app.post("/generate-from-text")
async def generate_from_text(payload: dict = Body(...)):
    text = payload.get("text", "")
    return safe_text_to_graph(text)


@app.post("/generate-text")
async def generate_text(payload: dict = Body(...)):
    text = payload.get("text", "")
    return safe_text_to_graph(text)


def process_uploaded_file(file_path: Path, suffix: str):
    if suffix == ".txt":
        return safe_text_to_graph(file_path.read_text(encoding="utf-8", errors="ignore"))

    if suffix == ".pdf":
        extracted_text = extract_pdf_text(str(file_path))
        return safe_text_to_graph(extracted_text)

    if suffix in [".csv", ".xlsx"]:
        return table_to_graph(str(file_path))

    if suffix in [".png", ".jpg", ".jpeg", ".webp"]:
        return image_to_graph(str(file_path))

    return {"nodes": [], "edges": [], "error": f"Unsupported file type: {suffix}"}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    try:
        suffix = Path(file.filename).suffix.lower()
        saved_name = f"{uuid.uuid4().hex}{suffix}"
        file_path = UPLOAD_DIR / saved_name

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        return process_uploaded_file(file_path, suffix)

    except Exception as e:
        traceback.print_exc()
        return {"nodes": [], "edges": [], "error": str(e)}


@app.post("/generate-file")
async def generate_file(file: UploadFile = File(...)):
    return await upload(file)