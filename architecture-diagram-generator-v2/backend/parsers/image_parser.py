import base64
import json
import re
import requests
from pathlib import Path
from PIL import Image

print("✅ NEW IMAGE PARSER LOADED - STRUCTURED JSON VERSION")

OLLAMA_URL = "http://localhost:11434/api/generate"
VISION_MODEL = "qwen2.5vl"


def preprocess_image(image_path):
    """
    Resize large images before sending to Qwen2.5VL.
    This helps reduce processing time.
    """
    img = Image.open(image_path).convert("RGB")

    max_width = 1400

    if img.width > max_width:
        ratio = max_width / img.width
        new_height = int(img.height * ratio)
        img = img.resize((max_width, new_height))

    new_path = str(Path(image_path).with_name("preprocessed_" + Path(image_path).name))
    img.save(new_path, quality=90)

    return new_path


def extract_json(text):
    """
    Extract JSON object from model response.
    Sometimes model returns explanation before/after JSON.
    This function extracts only the JSON part.
    """
    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"\{[\s\S]*\}", text)

    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass

    return None


def image_to_graph(image_path):
    try:
        # Resize image first
        image_path = preprocess_image(image_path)

        with open(image_path, "rb") as img:
            encoded = base64.b64encode(img.read()).decode("utf-8")

        prompt = """
You are an Industrial Control System architecture extractor.

Your task is to analyze the uploaded architecture image and extract structured JSON.

Do NOT draw a diagram.
Do NOT return nodes and edges.
Return ONLY valid JSON.
Do NOT write explanation.
Do NOT use markdown.
Do NOT wrap JSON inside ```.

Required JSON format:

{
  "roles": [
    {
      "id": "vendor_operator",
      "name": "Vendor Operator",
      "description": "Role inferred from vendor control room"
    }
  ],
  "assets": [
    {
      "id": "oem_scada_server",
      "name": "OEM SCADA Server",
      "type": "server",
      "zone": "wind_turbine_control_center",
      "criticality": "high"
    }
  ],
  "permissions": [
    {
      "subject": "vendor_operator",
      "object": "customer_vpn",
      "action": "establish_vpn",
      "reason": "Vendor operator can access through VPN"
    }
  ],
  "conduits": [
    {
      "source": "customer_vpn",
      "target": "vendor_firewall",
      "channel": "VPN connection",
      "enforcement": "vendor_firewall"
    }
  ]
}

Important extraction rules:

1. Extract every visible architecture component as an asset.
2. Use zones/rooms as the zone value of assets.
3. Extract visible connection lines as conduits.
4. Firewalls should have type "firewall".
5. VPNs should have type "vpn".
6. Servers should have type "server".
7. HMI should have type "hmi".
8. PLC should have type "control_device" and criticality "critical".
9. Distributed I/O should have type "io_device".
10. Physical components/sensors should have type "sensor" or "field_device".
11. If roles are not explicitly written, infer minimal roles from rooms:
    vendor_operator, customer_operator, wind_farm_operator.
12. Do not invent unrelated components.
13. Use lowercase underscore ids.
14. Return only this structure:
    roles, assets, permissions, conduits.

For this type of wind-farm ICS image, look carefully for these components if visible:

- OEM SCADA Server
- PCN
- OEM Firewall
- Wind Turbine Control Center
- Wind Turbine
- Master HMI
- Slave HMI
- PLC
- Distributed I/O
- Physical Components/Sensor
- Customer WAN
- Internet
- Customer VPN
- Vendor Firewall
- OEM Network Center
- Vendor Control Room
- Customer Firewall
- Customer Grid Control Server
- Customer Control Room
- Wind Farm Control Room Firewall
- Wind Farm Control Room Server
- Wind Farm Control Room
"""

        response = requests.post(
            OLLAMA_URL,
            json={
                "model": VISION_MODEL,
                "prompt": prompt,
                "images": [encoded],
                "stream": False,
                "options": {
                    "temperature": 0,
                    "num_predict": 2000
                }
            },
            timeout=240
        )

        response.raise_for_status()

        result = response.json()
        raw_text = result.get("response", "")

        print("\n===== RAW QWEN2.5VL OUTPUT =====")
        print(raw_text)
        print("===== END RAW QWEN2.5VL OUTPUT =====\n")

        graph = extract_json(raw_text)

        if graph:
            return {
                "roles": graph.get("roles", []),
                "assets": graph.get("assets", []),
                "permissions": graph.get("permissions", []),
                "conduits": graph.get("conduits", [])
            }

        return {
            "roles": [],
            "assets": [],
            "permissions": [],
            "conduits": [],
            "error": "Model did not return valid JSON. Check backend terminal raw output."
        }

    except requests.exceptions.ConnectionError:
        return {
            "roles": [],
            "assets": [],
            "permissions": [],
            "conduits": [],
            "error": "Ollama is not running. Start Ollama and check http://localhost:11434"
        }

    except requests.exceptions.Timeout:
        return {
            "roles": [],
            "assets": [],
            "permissions": [],
            "conduits": [],
            "error": "Qwen2.5VL timed out. Try a smaller or cropped image."
        }

    except Exception as e:
        return {
            "roles": [],
            "assets": [],
            "permissions": [],
            "conduits": [],
            "error": str(e)
        }