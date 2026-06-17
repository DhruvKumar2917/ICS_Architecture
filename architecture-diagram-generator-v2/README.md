# Architecture Diagram Generator V2

This project converts text, images, PDFs, CSV files, and Excel tables into editable architecture diagrams.

## Current Progress

The project is in a functional state. The backend can process various file types and generate a graph representation. The frontend is a simple interface to upload files and visualize the generated diagram.

### Implemented Features
- **Backend API:** A FastAPI server with endpoints to handle file uploads and text processing.
- **File Parsing:**
  - `.txt`: Extracts text and converts it to a graph.
  - `.pdf`: Extracts text using `pymupdf` and converts it to a graph.
  - `.csv`, `.xlsx`: Parses tables using `pandas` and `openpyxl` and converts them to a graph.
  - `.png`, `.jpg`, `.jpeg`, `.webp`: Uses an image-to-graph parser (details in `image_parser.py`).
- **Frontend:** A basic React application that allows users to upload files and view the generated diagram.

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