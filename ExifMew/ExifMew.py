#!/usr/bin/env python3
# EXIFMEW - Court Ready Single File Media Analyzer (With GPS + Chain of Custody)

import hashlib
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from reportlab.platypus import Image as RLImage
from datetime import datetime

try:
    from PIL import Image, ExifTags
    PIL_OK = True
except Exception:
    PIL_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle , Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors 
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False


# ---------------- Utility ----------------
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def human_size(num_bytes: int) -> str:
    for unit in ['B','KB','MB','GB']:
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} TB"

def detect_mime(path: Path):
    mime, _ = mimetypes.guess_type(str(path))
    return mime


# ---------------- GPS Helpers ----------------
def _ratio_to_float(r):
    try:
        if isinstance(r, tuple):
            return float(r[0]) / float(r[1])
        return float(r)
    except Exception:
        return 0.0

def gps_to_decimal(gps_info: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    try:
        lat = gps_info.get("GPSLatitude")
        lat_ref = gps_info.get("GPSLatitudeRef")
        lon = gps_info.get("GPSLongitude")
        lon_ref = gps_info.get("GPSLongitudeRef")

        if not (lat and lat_ref and lon and lon_ref):
            return None, None

        def convert(dms):
            d = _ratio_to_float(dms[0])
            m = _ratio_to_float(dms[1])
            s = _ratio_to_float(dms[2])
            return d + (m / 60.0) + (s / 3600.0)

        lat_val = convert(lat)
        lon_val = convert(lon)

        if lat_ref.upper() == "S":
            lat_val = -lat_val
        if lon_ref.upper() == "W":
            lon_val = -lon_val

        return round(lat_val, 8), round(lon_val, 8)

    except Exception:
        return None, None


# ---------------- Image Metadata ----------------
def extract_image_meta(path: Path) -> Dict[str, Any]:
    meta = {}

    if not PIL_OK:
        meta["error"] = "Pillow not installed."
        return meta

    try:
        with Image.open(path) as img:
            exif = img._getexif() or {}
            gps_info = None

            for tag_id, val in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)

                if tag == "Make":
                    meta["device_make"] = val
                if tag == "Model":
                    meta["device_model"] = val
                if tag == "Software":
                    meta["software"] = val
                if tag in ("DateTimeOriginal", "DateTimeDigitized"):
                    meta["datetime_taken"] = val

                if tag == "GPSInfo":
                    gps_info = {}
                    for key in val:
                        gps_tag = ExifTags.GPSTAGS.get(key, key)
                        gps_info[gps_tag] = val[key]

            if gps_info:
                lat, lon = gps_to_decimal(gps_info)
                meta["latitude"] = lat
                meta["longitude"] = lon

                if "GPSAltitude" in gps_info:
                    meta["altitude_meters"] = _ratio_to_float(gps_info["GPSAltitude"])
                else:
                    meta["altitude_meters"] = None
            else:
                meta["latitude"] = None
                meta["longitude"] = None
                meta["altitude_meters"] = None

    except Exception as e:
        meta["error"] = str(e)

    return meta

# ---------------- PDF Export ----------------
def export_pdf(path: Path, report: Dict[str, Any]):
    doc = SimpleDocTemplate(str(path), pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    #Image logo section
    script_dir = Path(__file__).resolve().parent
    logo_path = script_dir / "logo.png"

    if logo_path.exists():
        Image = RLImage(str(logo_path))
        Image.drawHeight = 90
        Image.drawWidth = 140
        story.append(Image)
        story.append(Spacer(1, 10))

    story.append(Paragraph("<b>EXIFMEW - Digital Forensic Report</b>", styles["Title"]))
    story.append(Spacer(1, 12))

    def section(title, fields):
        story.append(Paragraph(f"<b>{title}</b>", styles["Heading2"]))
        story.append(Spacer(1, 6))
        table_data = [[k, str(v if v is not None else "N/A")] for k, v in fields.items()]
        table = Table(table_data, colWidths=[70*mm, 90*mm])
        table.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("FONTSIZE", (0,0), (-1,-1), 9),
        ]))
        story.append(table)
        story.append(Spacer(1, 12))

    section("Case Information", {
        "Case ID": report.get("Case ID"),
        "Investigator": report.get("Investigator"),
        "Analysis Date (UTC)": report.get("Analyzed UTC")
    })

    # Insert paragraph here
    story.append(Paragraph("<b>Examination Summary</b>", styles["Heading2"]))
    story.append(Spacer(1, 6))

    story.append(Paragraph(
    "This report documents the forensic examination of the specified digital media file. "
    "The analysis was conducted in a read-only forensic manner to preserve evidence integrity. "
    "Cryptographic hashing (SHA256) was performed to uniquely identify the file at the time of examination. "
    "Embedded metadata, including device identifiers, timestamps, and geolocation data (if present), "
    "were extracted and documented in accordance with digital forensic best practices.",
    styles["Normal"]
))

    story.append(Spacer(1, 12))
    section("File Information", {
        "File Path": report.get("File Path"),
        "MIME Type": report.get("MIME Type"),
        "File Size": report.get("File Size"),
        "SHA256": report.get("SHA256")
    })
    #Digital Evidence Image insert
    file_path = Path(report.get("File Path"))
    if file_path.exists() and file_path.suffix.lower() in [".jpg", ".jpeg", ".png"]:
        story.append(Paragraph("<b>4. Evidence Image Preview</b>", styles["Heading2"]))
        story.append(Spacer(1, 6))
        preview = RLImage(str(file_path))
        preview.drawWidth = 60 * mm
        preview.drawHeight = 45 * mm
        story.append(preview)
        story.append(Spacer(1, 14))

    section("Media Metadata", {
        "Date/Time Taken": report.get("datetime_taken"),
        "Device Make": report.get("device_make"),
        "Device Model": report.get("device_model"),
        "Software": report.get("software")
    })

    section("GPS Information", {
        "Latitude": report.get("latitude"),
        "Longitude": report.get("longitude"),
        "Altitude (meters)": report.get("altitude_meters"),
        "Google Maps": f"https://www.google.com/maps?q={report.get('latitude')},{report.get('longitude')}"
        if report.get("latitude") and report.get("longitude") else "N/A"
    })

    section("Integrity Verification", {
        "Hash Algorithm": "SHA256",
        "Verification Statement": "This hash uniquely represents the file at time of examination."
    })

    section("Digital Signature", {
        "Signature": "_________________________",
        "Name": report.get("Investigator"),
        "Date": report.get("Analyzed UTC")
    })

    doc.build(story)


# ---------------- Main ----------------
def main():
    print(r"""
//  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\ 
// ( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )
//  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ < 
//  /\_/\                                                          /\_/\ 
// ( o.o )                                                        ( o.o )
//  > ^ <       _______  _____ _____ __  __ _______        __      > ^ < 
//  /\_/\      | ____\ \/ /_ _|  ___|  \/  | ____\ \      / /      /\_/\ 
// ( o.o )     |  _|  \  / | || |_  | |\/| |  _|  \ \ /\ / /      ( o.o )
//  > ^ <      | |___ /  \ | ||  _| | |  | | |___  \ V  V /        > ^ < 
//  /\_/\      |_____/_/\_\___|_|   |_|  |_|_____|  \_/\_/         /\_/\ 
// ( o.o )                                                        ( o.o )
//  > ^ <                                                          > ^ < 
//  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\  /\_/\ 
// ( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )( o.o )
//  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ <  > ^ < 
          """)

    case_id = input("Enter Case ID: ")
    investigator = input("Enter Investigator Name: ")
    file_path = input("Enter full path to media file: ").strip().strip('"')
    

    path = Path(file_path)
    if not path.exists():
        print("File not found.")
        return

    mime = detect_mime(path)
    sha = sha256_file(path)
    size = path.stat().st_size

    report = {
        "Case ID": case_id,
        "Investigator": investigator,
        "File Path": str(path),
        "MIME Type": mime,
        "File Size": human_size(size),
        "SHA256": sha,
        "Analyzed UTC": datetime.now(timezone.utc).isoformat()
    }

    if mime and mime.startswith("image/"):
        report.update(extract_image_meta(path))

    print("\n--- Analysis Result ---")
    for k, v in report.items():
        print(f"{k}: {v}")

    if report.get("latitude") and report.get("longitude"):
        print(f"\nGoogle Maps: https://www.google.com/maps?q={report['latitude']},{report['longitude']}")

    save = input("\nExport to PDF? (y/n): ").lower()
    if save == "y":

    # Get directory where exifmew.py is located
        script_dir = Path(__file__).resolve().parent

    # Create DFIR_Report folder inside script directory
    report_dir = script_dir / "DFIR_Report"
    report_dir.mkdir(parents=True, exist_ok=True)

    # Create filename
    pdf_path = report_dir / f"{path.stem}_FORENSIC_REPORT.pdf"

    export_pdf(pdf_path, report)

    print(f"\nPDF saved to: {pdf_path}")


if __name__ == "__main__":
    main()