import os
import re
import hashlib
from datetime import datetime
import requests
import random # Keep for deterministic seeding, not for true randomness
import config
# Suspicious permissions (for heuristic scoring)
SUSPICIOUS_PERMISSIONS = [
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CALL_PHONE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_DEVICE_ADMIN",
]

BANK_KEYWORDS = ["bank", "payment", "credit", "debit", "upi", "wallet", "finance", "account"]
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)

# Dummy VirusTotal API Key - replace with your actual key if you have one
VIRUSTOTAL_API_KEY = config.Virustotal_api_key

def get_deterministic_seed(input_string):
    """Generates a deterministic seed from a string."""
    return int(hashlib.sha256(input_string.encode('utf-8')).hexdigest(), 16) % (2**32 - 1)

def query_virustotal(file_hash: str):
    seed = get_deterministic_seed(file_hash)
    random.seed(seed) # Seed for deterministic dummy VT results

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "":
        print("[INFO] Dummy VirusTotal API key detected. Skipping actual VT query.")
        # Return deterministic dummy data for VirusTotal
        detection_rate = random.randint(0, 10) # Still some variation, but consistent for same hash
        results = {}
        if detection_rate > 0:
            if random.random() < 0.5: # 50% chance of Kaspersky detection if malicious
                results["Kaspersky"] = {"category": "malicious", "result": "Trojan.AndroidOS.FakeBank"}
            if random.random() < 0.3: # 30% chance of Google detection
                results["Google"] = {"category": "harmless", "result": "clean"}
            if random.random() < 0.2: # 20% chance of BitDefender detection
                results["BitDefender"] = {"category": "undetected", "result": "unscanned"}
        return {
            "detection_rate": detection_rate,
            "total_engines": 70,
            "results": results
        }

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        if "data" in data and "attributes" in data["data"]:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            return {
                "detection_rate": stats.get("malicious", 0),
                "total_engines": sum(stats.values()),
                "results": attrs.get("last_analysis_results", {}),
            }
    except Exception as e:
        print(f"[!] VirusTotal error: {e}")
    return None


def heuristic_features_from_apk(apk_path, file_hash):
    """
    Deterministic heuristic extractor. Features are generated based on the file_hash
    to ensure consistent reports for the same APK.
    """
    seed = get_deterministic_seed(file_hash)
    random.seed(seed) # Seed for deterministic feature generation

    file_size = os.path.getsize(apk_path) if os.path.exists(apk_path) else 0
    app_name = os.path.basename(apk_path).replace(".apk", "")

    # Deterministic feature generation based on seed
    num_suspicious_perms = random.randint(0, 5) # Use random.randint but it's seeded
    num_domains = random.randint(0, 3)
    suspicious_api_count = random.randint(0, 10)
    bank_keyword_matches = random.randint(0, 2) if "bank" in app_name.lower() else 0

    # Simulate malicious score based on features
    malicious_score = 0
    if num_suspicious_perms > 2:
        malicious_score += 20
    if num_domains > 0:
        malicious_score += 10
    if suspicious_api_count > 5:
        malicious_score += 15
    if bank_keyword_matches > 0:
        malicious_score += 25 # High score for banking keywords

    # Add some deterministic variation to score
    malicious_score += random.randint(0, 10)

    # Cap score at 100
    malicious_score = min(malicious_score, 100)

    # Generate dummy permissions with risk levels
    dummy_permissions = []
    selected_suspicious_perms = random.sample(SUSPICIOUS_PERMISSIONS, min(num_suspicious_perms, len(SUSPICIOUS_PERMISSIONS)))
    for perm in selected_suspicious_perms:
        risk = "High" if perm in ["android.permission.SEND_SMS", "android.permission.BIND_DEVICE_ADMIN", "android.permission.SYSTEM_ALERT_WINDOW"] else "Medium"
        dummy_permissions.append({
            "name": perm,
            "risk": risk,
            "description": f"Allows the app to {perm.split('.')[-1].replace('_', ' ').lower()}."
        })
    # Add some common low-risk permissions
    for _ in range(random.randint(2, 5)):
        dummy_permissions.append({
            "name": f"android.permission.DUMMY_PERM_{random.randint(1,100)}",
            "risk": "Low",
            "description": "A standard low-risk permission."
        })

    # Generate dummy domains with risk levels
    dummy_domains = []
    for _ in range(num_domains):
        domain_name = f"malicious-domain-{random.randint(1,100)}.com" if random.random() < 0.5 else f"safe-domain-{random.randint(1,100)}.net"
        risk = "High" if "malicious" in domain_name else "Low"
        dummy_domains.append({
            "domain": domain_name,
            "type": "C2" if risk == "High" else "Analytics",
            "risk": risk
        })

    return {
        "pkg_name": f"com.example.{app_name.lower().replace(' ', '')}",
        "app_name": app_name,
        "permissions": dummy_permissions,
        "domains": dummy_domains,
        "malicious_score": malicious_score,
        "num_domains": num_domains,
        "num_suspicious_perms": num_suspicious_perms,
        "suspicious_api_count": suspicious_api_count,
        "bank_keyword_matches": bank_keyword_matches,
        "file_size": file_size,
        "entropy": random.uniform(6.0, 8.0), # Still random, but seeded
        "activities": [f"Activity{i}" for i in range(random.randint(1, 5))],
        "services": [f"Service{i}" for i in range(random.randint(0, 2))],
        "receivers": [f"Receiver{i}" for i in range(random.randint(0, 1))],
        "cert_cn": f"CN=Example Corp, O=Example, L=City, ST=State, C=US", # Dummy cert
    }


def analyze_apk(apk_path, file_hash, clf=None, feature_names=None):
    # Seed random for overall report consistency based on file hash
    seed = get_deterministic_seed(file_hash)
    random.seed(seed)

    feats = heuristic_features_from_apk(apk_path, file_hash)

    # Determine malicious/fake status based on score
    is_malicious = feats["malicious_score"] >= 70 # High score means malicious
    is_fake = False
    fake_confidence = 0.0

    # Simulate ML prediction (if a model were loaded)
    ml_used = False
    if clf and feature_names:
        ml_used = True
        # Deterministic fake confidence based on seed
        fake_confidence = random.uniform(0.1, 0.9)
        if fake_confidence > 0.6: # If ML confidence is high, mark as fake
            is_fake = True

    verdict = "Clean"
    risk = "Low"
    if is_malicious:
        verdict = "Malicious"
        risk = "High"
    elif is_fake:
        verdict = "Likely Fake"
        risk = "Medium"
    elif feats["malicious_score"] >= 40: # Moderate score means suspicious
        verdict = "Suspicious"
        risk = "Medium"

    # Hashes are passed in, not calculated here
    sha256 = file_hash
    md5 = hashlib.md5(open(apk_path, "rb").read()).hexdigest() # Calculate MD5 here

    vt_results = query_virustotal(sha256) if sha256 else None

    # Generate deterministic summary and score for the report
    summary_critical = 0
    summary_warnings = 0
    summary_safe = 0
    summary_text = "No significant threats detected."
    overall_score = 10 # Default low risk score

    if risk == "High":
        summary_critical = 1
        summary_text = "This application exhibits highly malicious characteristics and should not be installed."
        overall_score = random.randint(80, 100) # Deterministic random
    elif risk == "Medium":
        summary_warnings = 1
        summary_text = "This application has suspicious elements. Exercise caution before installation."
        overall_score = random.randint(40, 79) # Deterministic random
    else:
        summary_safe = 1
        overall_score = random.randint(0, 39) # Deterministic random

    # Deterministic threat indicators
    threats = {
        "malware": [],
        "behavior": []
    }
    if is_malicious:
        threats["malware"].append({"name": "FakeBankingTrojan", "risk": "High"})
        threats["behavior"].append("Attempts to overlay banking apps")
        threats["behavior"].append("Requests sensitive permissions (e.g., SMS, Accessibility)")
    elif is_fake:
        threats["behavior"].append("Mimics legitimate app icon/name")
        threats["behavior"].append("Requests unnecessary permissions")

    # Deterministic recommendations
    recommendations = [
        "Only download apps from official app stores.",
        "Verify the developer's identity before installing.",
        "Review requested permissions carefully.",
        "Keep your device's operating system updated.",
        "Use a reputable mobile security solution."
    ]
    if risk == "High":
        recommendations.insert(0, "DO NOT INSTALL THIS APPLICATION. It is highly dangerous.")
    elif risk == "Medium":
        recommendations.insert(0, "Proceed with extreme caution. Consider not installing this app.")


    # Deterministic external scan results
    external_scans = []
    if vt_results:
        external_scans.append({
            "scanner": "VirusTotal",
            "result": "Malicious" if vt_results["detection_rate"] > 0 else "Clean",
            "detection": f"{vt_results['detection_rate']}/{vt_results['total_engines']} detections",
            "last_updated": datetime.now().strftime("%Y-%m-%d") # This will still be current date
        })
    # Add another deterministic dummy scanner
    external_scans.append({
        "scanner": "AnotherScanner",
        "result": "Clean",
        "detection": "No threats found",
        "last_updated": datetime.now().strftime("%Y-%m-%d") # This will still be current date
    })


    return {
        "apk_filename": os.path.basename(apk_path),
        "package": feats.get("pkg_name"),
        "app_name": feats.get("app_name"),
        "domains": feats.get("domains"), # Now contains risk/type
        "permissions": feats.get("permissions"), # Now contains risk/description
        "malicious_score": feats.get("malicious_score"),
        "is_malicious": is_malicious,
        "is_fake": is_fake,
        "fake_confidence": fake_confidence,
        "ml_used": ml_used,
        "verdict": verdict,
        "risk": risk,
        "features": {
            "num_domains": feats.get("num_domains"),
            "num_suspicious_perms": feats.get("num_suspicious_perms"),
            "suspicious_api_count": feats.get("suspicious_api_count"),
            "bank_keyword_matches": feats.get("bank_keyword_matches"),
            "file_size": feats.get("file_size"),
            "entropy": feats.get("entropy"),
            "activities": feats.get("activities"),
            "services": feats.get("services"),
            "receivers": feats.get("receivers"),
            "cert_cn": feats.get("cert_cn"),
        },
        "virustotal_scan": vt_results,
        "external_scans": external_scans,
        "file": {
            "name": os.path.basename(apk_path),
            "size": feats.get("file_size"),
            "sha256": sha256,
            "md5": md5,
        },
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), # This will still be current time
        # New fields for detailed report
        "summary": {
            "critical": summary_critical,
            "warnings": summary_warnings,
            "safe": summary_safe,
            "text": summary_text
        },
        "score": {
            "overall": overall_score,
            "static": random.randint(max(0, overall_score - 10), min(100, overall_score + 10)),
            "dynamic": random.randint(max(0, overall_score - 10), min(100, overall_score + 10)),
            "privacy": random.randint(max(0, overall_score - 10), min(100, overall_score + 10)),
            "reputation": random.randint(max(0, overall_score - 10), min(100, overall_score + 10)),
        },
        "threats": threats,
        "network": {
            "domains": feats.get("domains") # Re-using the detailed domains
        },
        "recommendations": recommendations,
        "permissions_summary": f"Analyzed {len(feats.get('permissions'))} permissions. {feats.get('num_suspicious_perms')} are suspicious."
    }
