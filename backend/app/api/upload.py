import shutil
import uuid
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, File, UploadFile, Query

from app.parsers.rbac.parser import parse_rbac
from app.parsers.firewall.parser import FirewallParser
from app.parsers.image.parser import image_to_graph
from app.parsers.unified_model import build_unified_model
from app.api.analysis import run_security_analysis

router = APIRouter()

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


async def _read_text(uploaded_file: Optional[UploadFile]) -> str:
    if not uploaded_file:
        return ""
    try:
        content_bytes = await uploaded_file.read()
        await uploaded_file.seek(0)
        return content_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[read_text] Error: {e}")
        return ""


def _convert_pdf_to_image(pdf_path: str) -> str:
    import fitz
    doc  = fitz.open(pdf_path)
    page = doc.load_page(0)
    pix  = page.get_pixmap(dpi=150)
    img_path = pdf_path.replace(".pdf", "_rendered.jpg")
    pix.save(img_path)
    return img_path


@router.post("/upload")
async def upload(
    file: Optional[UploadFile]             = File(None),
    architecture_file: Optional[UploadFile] = File(None),
    rbac_file:         Optional[UploadFile] = File(None),
    firewall_file:     Optional[UploadFile] = File(None),
    role: str = Query(None),
):
    try:
        arch_file = architecture_file or file
        if not arch_file:
            return {"error": "No architecture file uploaded. Please provide an architecture diagram."}

        suffix     = Path(arch_file.filename).suffix.lower()
        saved_name = f"{uuid.uuid4().hex}{suffix}"
        file_path  = UPLOAD_DIR / saved_name

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(arch_file.file, buffer)

        rbac_text    = await _read_text(rbac_file)
        rbac_data    = parse_rbac(rbac_text) if rbac_text else {"S": [], "R": [], "permissions": []}
        rbac_summary = rbac_data.copy()
        print(f"[upload] RBAC: {len(rbac_data.get('S', []))} subjects, "
              f"{len(rbac_data.get('R', []))} actions, "
              f"{len(rbac_data.get('permissions', []))} permissions", flush=True)
        if rbac_data.get("S"):
            subj_names = ", ".join(s.get("id","?") for s in rbac_data["S"][:6])
            print(f"[upload]   Subjects: {subj_names}", flush=True)
        if rbac_text and not rbac_data.get("S"):
            print("[upload] [WARN] WARNING: RBAC file was uploaded but no subjects were extracted. "
                  "Check RBAC file format.", flush=True)

        fw_text      = await _read_text(firewall_file)
        fw_parser    = FirewallParser().parse(fw_text) if fw_text else None
        fw_summary   = fw_parser.to_dict() if fw_parser else {"rules": [], "allowed_pairs": [], "allowed_count": 0}
        if fw_parser:
            print(f"[upload] Firewall: {len(fw_parser.rules)} rules, "
                  f"{len(fw_parser.allowed_pairs)} allowed pairs", flush=True)
        else:
            print("[upload] Firewall: No firewall file - all architecture connections will be included in Ec", flush=True)

        if suffix in (".png", ".jpg", ".jpeg", ".webp"):
            arch_raw = image_to_graph(str(file_path))
        elif suffix == ".pdf":
            try:
                img_path = _convert_pdf_to_image(str(file_path))
                arch_raw = image_to_graph(img_path)
            except Exception as e:
                print(f"[upload] PDF->image failed: {e}; trying text extraction", flush=True)
                arch_raw = {"raw_model_data": {}, "error": str(e)}
        else:
            return {"error": f"Unsupported architecture file type: {suffix}"}

        if "error" in arch_raw and not arch_raw.get("raw_model_data"):
            return arch_raw

        arch_data = arch_raw.get("raw_model_data", arch_raw)

        print(f"[upload] Architecture extracted: "
              f"{len(arch_data.get('Z', arch_data.get('zones', [])))} zones, "
              f"{len(arch_data.get('O', arch_data.get('assets', [])))} objects, "
              f"{len((arch_data.get('E') or {}).get('connections', arch_data.get('communications', [])))} connections",
              flush=True)

        unified_data = build_unified_model(arch_data, rbac_data, fw_parser)

        print(f"[upload] Unified model: "
              f"Z={len(unified_data.get('Z',[]))}, "
              f"S={len(unified_data.get('S',[]))}, "
              f"O={len(unified_data.get('O',[]))}, "
              f"R={len(unified_data.get('R',[]))}, "
              f"Ea={len((unified_data.get('E') or {}).get('Ea',[]))}, "
              f"Ec={len((unified_data.get('E') or {}).get('Ec',[]))}, "
              f"blocked={len(unified_data.get('firewall_blocked',[]))}",
              flush=True)

        return run_security_analysis(unified_data, rbac_summary, fw_summary, selected_role=role)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}
