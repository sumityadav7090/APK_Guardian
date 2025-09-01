import os
import uuid
import json
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, render_template
from werkzeug.utils import secure_filename

from analyzer import analyze_apk # Import the modified analyzer
from model import load_or_train_model # Import model loading

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
ALLOWED_EXTENSIONS = {"apk"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

app = Flask(__name__, template_folder="templates")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER

# Load ML model once at startup
clf, feature_names = load_or_train_model()
print("[INFO] ML model loaded successfully.")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_file_sha256(filepath):
    """Calculates the SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)  # Read in 8KB chunks
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def fill_defaults(report: dict) -> dict:
    """Ensure all frontend-required fields are present and have default values."""
    default_report = {
        "report_id": "",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "apk_filename": "",
        "package": "unknown",
        "app_name": "unknown",
        "domains": [],
        "permissions": [],
        "malicious_score": 0,
        "is_malicious": False,
        "is_fake": False,
        "fake_confidence": 0.0,
        "ml_used": False,
        "features": {
            "num_domains": 0,
            "num_suspicious_perms": 0,
            "suspicious_api_count": 0,
            "bank_keyword_matches": 0,
            "file_size": 0,
            "entropy": 0,
            "activities": [],
            "services": [],
            "receivers": [],
            "cert_cn": None,
        },
        "virustotal_scan": None,
        "file": {
            "name": "",
            "size": 0,
            "sha256": "",
            "md5": ""
        },
        "verdict": "Unknown",
        "risk": "Low",
        "external_scans": [],
        "summary": {
            "critical": 0,
            "warnings": 0,
            "safe": 0,
            "text": "No summary available."
        },
        "score": {
            "overall": 0,
            "static": 0,
            "dynamic": 0,
            "privacy": 0,
            "reputation": 0,
        },
        "threats": {
            "malware": [],
            "behavior": []
        },
        "network": {
            "domains": []
        },
        "recommendations": [],
        "permissions_summary": "No permission summary available."
    }

    for key, value in report.items():
        if key in default_report and isinstance(default_report[key], dict) and isinstance(value, dict):
            default_report[key].update(value)
        else:
            default_report[key] = value
    return default_report


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze_apk", methods=["POST"])
def analyze_apk_route():
    if "apkFile" not in request.files and "apk_file" not in request.files:
        print("[ERROR] No file uploaded in analyze_apk_route")
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files.get("apkFile") or request.files.get("apk_file")
    if file.filename == "" or not allowed_file(file.filename):
        print(f"[ERROR] Invalid file type. Filename: '{file.filename}'")
        return jsonify({"error": "Invalid file type. Please upload .apk only"}), 400

    filename = secure_filename(file.filename)
    temp_save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename) # Save temporarily to calculate hash

    try:
        file.save(temp_save_path)
        print(f"[INFO] File saved temporarily to: {temp_save_path}")
    except Exception as e:
        print(f"[ERROR] Failed to save temporary file {temp_save_path}: {e}")
        return jsonify({"error": f"Failed to save file: {e}"}), 500

    # Calculate SHA256 hash of the uploaded file
    file_sha256 = calculate_file_sha256(temp_save_path)
    print(f"[INFO] Calculated SHA256 for {filename}: {file_sha256}")

    # Define the permanent path using the SHA256 hash
    # This ensures unique storage and easy lookup
    permanent_filename = f"{file_sha256}.apk"
    permanent_save_path = os.path.join(app.config["UPLOAD_FOLDER"], permanent_filename)

    # Check if the file already exists at the permanent path
    if os.path.exists(permanent_save_path) and os.path.samefile(temp_save_path, permanent_save_path):
        # If the file was saved directly to its permanent location (e.g., if filename was already hash.apk)
        pass
    elif os.path.exists(permanent_save_path):
        # If the file already exists, remove the temporary upload
        os.remove(temp_save_path)
        print(f"[INFO] APK {filename} (SHA256: {file_sha256}) already exists. Using existing file.")
    else:
        # Move the temporary file to its permanent location
        os.rename(temp_save_path, permanent_save_path)
        print(f"[INFO] APK {filename} moved to permanent path: {permanent_save_path}")

    # Check if a report for this SHA256 already exists
    report_id_from_hash = file_sha256 # Use SHA256 as report ID for direct mapping
    report_file_path = os.path.join(app.config["REPORT_FOLDER"], f"{report_id_from_hash}.json")

    if os.path.exists(report_file_path):
        try:
            with open(report_file_path, "r") as f:
                cached_report = json.load(f)
            print(f"[INFO] Returning cached report for SHA256: {file_sha256}")
            return jsonify(fill_defaults(cached_report))
        except json.JSONDecodeError as e:
            print(f"[ERROR] Cached report for {file_sha256} is corrupted: {e}. Re-analyzing.")
            # Proceed to re-analyze if cached report is corrupted
        except Exception as e:
            print(f"[ERROR] Error reading cached report for {file_sha256}: {e}. Re-analyzing.")
            # Proceed to re-analyze if there's another error

    # Analyze if no cached report or if cached report was corrupted
    raw_result = {}
    try:
        # Pass the file_sha256 to analyzer.py for deterministic feature generation
        raw_result = analyze_apk(permanent_save_path, file_sha256, clf=clf, feature_names=feature_names)
        print(f"[INFO] APK analysis completed for {filename} (SHA256: {file_sha256})")
    except Exception as e:
        print(f"[ERROR] APK analysis failed for {filename} (SHA256: {file_sha256}): {e}")
        raw_result = {
            "apk_filename": filename,
            "app_name": filename,
            "verdict": "Analysis Failed",
            "risk": "Unknown",
            "summary": {"text": f"Analysis failed due to an internal error: {e}"}
        }

    # Set report_id to the SHA256 hash for consistent lookup
    raw_result["report_id"] = report_id_from_hash
    raw_result["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_result["file"]["sha256"] = file_sha256 # Ensure SHA256 is correctly set in the report
    raw_result["file"]["name"] = filename # Keep original filename in report

    result = fill_defaults(raw_result)

    # Save new report
    try:
        with open(report_file_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[INFO] New report saved to: {report_file_path}")
    except Exception as e:
        print(f"[ERROR] Failed to save report {report_file_path}: {e}")
        return jsonify({"error": f"Failed to save report: {e}"}), 500

    return jsonify(result)


@app.route("/api/report")
def get_report():
    report_id = request.args.get("id")
    if not report_id:
        print("[ERROR] get_report: No report ID provided.")
        return jsonify({"verdict": "No report", "error": "No report ID provided"}), 404

    report_path = os.path.join(app.config["REPORT_FOLDER"], f"{report_id}.json")
    if not os.path.exists(report_path):
        print(f"[ERROR] get_report: Report file not found at {report_path}")
        return jsonify({"verdict": "No report", "error": "Report file not found"}), 404

    try:
        with open(report_path, "r") as f:
            data = json.load(f)
        print(f"[INFO] get_report: Successfully loaded report {report_id}")
    except json.JSONDecodeError as e:
        print(f"[ERROR] get_report: JSON decode error for {report_path}: {e}")
        return jsonify({"verdict": "Error reading report file", "error": f"JSON decode error: {e}"}), 500
    except Exception as e:
        print(f"[ERROR] get_report: Unexpected error reading report {report_path}: {e}")
        return jsonify({"verdict": "Error reading report file", "error": f"Unexpected error: {e}"}), 500

    return jsonify(fill_defaults(data))


@app.route("/api/dashboard-data")
def dashboard_data():
    total_apks_scanned = 0
    malicious_detected = 0
    trusted_certificates = 0
    high_risk_permissions = 0
    safety_distribution = {"safe": 0, "warning": 0, "malicious": 0}
    dangerous_permissions_counts = {}
    recent_scans_data = {}

    for report_file in os.listdir(app.config["REPORT_FOLDER"]):
        if report_file.endswith(".json"):
            report_path = os.path.join(app.config["REPORT_FOLDER"], report_file)
            try:
                with open(report_path, "r") as f:
                    report = json.load(f)
                    report = fill_defaults(report)

                    total_apks_scanned += 1 # Count reports, not files in uploads

                    if report.get("is_malicious"):
                        malicious_detected += 1
                        safety_distribution["malicious"] += 1
                    elif report.get("is_fake") or report.get("risk") == "Medium":
                        safety_distribution["warning"] += 1
                    else:
                        safety_distribution["safe"] += 1

                    for perm in report.get("permissions", []):
                        if perm.get("risk") == "High":
                            high_risk_permissions += 1
                            dangerous_permissions_counts[perm.get("name")] = dangerous_permissions_counts.get(perm.get("name"), 0) + 1

                    created_date = report.get("created_at", "").split(" ")[0]
                    if created_date:
                        recent_scans_data[created_date] = recent_scans_data.get(created_date, 0) + 1

            except Exception as e:
                print(f"[ERROR] Error processing report file {report_file} for dashboard: {e}")

    sorted_recent_scans = [{"date": date, "count": count} for date, count in recent_scans_data.items()]
    sorted_recent_scans.sort(key=lambda x: x["date"])

    sorted_dangerous_perms = dict(sorted(dangerous_permissions_counts.items(), key=lambda item: item[1], reverse=True)[:5])

    stats = {
        "totalApksScanned": total_apks_scanned,
        "maliciousDetected": malicious_detected,
        "trustedCertificates": trusted_certificates,
        "highRiskPermissions": high_risk_permissions,
        "safetyDistribution": safety_distribution,
        "dangerousPermissions": sorted_dangerous_perms,
        "recentScans": sorted_recent_scans,
    }
    return jsonify(stats)


@app.route("/reports/<path:filename>")
def download_report(filename):
    return send_from_directory(app.config["REPORT_FOLDER"], filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
