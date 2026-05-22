import fitz

def extract_pdf_text(path):
    doc = fitz.open(path)
    text = ""

    for i, page in enumerate(doc):
        page_text = page.get_text("text")
        print(f"===== PAGE {i+1} TEXT LENGTH: {len(page_text)} =====")
        print(page_text[:1000])
        text += "\n" + page_text

    print("===== TOTAL PDF TEXT LENGTH =====")
    print(len(text))

    return text