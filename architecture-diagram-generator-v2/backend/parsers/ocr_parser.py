import easyocr
import cv2
from pathlib import Path


_reader = None


def get_reader():
    """
    Loads EasyOCR reader only once.
    This avoids reloading model again and again.
    """
    global _reader

    if _reader is None:
        _reader = easyocr.Reader(["en"], gpu=False)

    return _reader


def preprocess_for_ocr(image_path):
    """
    Improves image quality for OCR.
    """
    image = cv2.imread(str(image_path))

    if image is None:
        return str(image_path)

    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Enlarge image slightly for small text
    scale_percent = 160
    width = int(gray.shape[1] * scale_percent / 100)
    height = int(gray.shape[0] * scale_percent / 100)
    resized = cv2.resize(gray, (width, height), interpolation=cv2.INTER_CUBIC)

    # Basic thresholding
    _, thresh = cv2.threshold(resized, 180, 255, cv2.THRESH_BINARY)

    output_path = Path(image_path).with_name("ocr_preprocessed_" + Path(image_path).name)
    cv2.imwrite(str(output_path), thresh)

    return str(output_path)


def extract_ocr_text(image_path):
    """
    Extracts visible text from architecture image.
    Returns plain OCR text.
    """
    try:
        processed_path = preprocess_for_ocr(image_path)

        reader = get_reader()
        results = reader.readtext(processed_path)

        lines = []

        for bbox, text, confidence in results:
            if confidence >= 0.25:
                lines.append(text)

        return "\n".join(lines)

    except Exception as e:
        return f"OCR_ERROR: {str(e)}"