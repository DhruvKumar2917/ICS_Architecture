# Architecture Diagram Generator V2

This project converts text, images, PDFs, CSV files, and Excel tables into editable architecture diagrams.

## Pipeline

Input → FastAPI Parser → JSON Graph → React Flow Renderer → Editable Diagram

## Backend run

```bash
cd backend
python -m venv venv
source venv/Scripts/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Frontend run

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open:

```bash
http://localhost:5173
```

## Optional Ollama vision setup

Install Ollama, then run:

```bash
ollama pull llava
ollama serve
```

Then upload an image screenshot.

If Ollama is not running, image upload returns a demo graph.
