from fastapi import APIRouter
from pydantic import BaseModel
import re
import base64
import requests
import os
import dns.resolver
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")
PHISHING_CHECK_API = "https://www.virustotal.com/api/v3/urls"

router = APIRouter()

SUSPICIOUS_KEYWORDS = [
    "urgent", "bank", "password", "login", "account", "verify", "click here",
    "suspend", "risk", "security alert", "update now", "limited time", "winner"
]

class EmailInput(BaseModel):
    subject: str
    body: str
    sender: str

def extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s\'"<>]+', text)

def check_url_safety(url: str) -> str:
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": API_KEY}

        response = requests.get(f"{PHISHING_CHECK_API}/{url_id}", headers=headers)

        if response.status_code == 404:
            submit_resp = requests.post(PHISHING_CHECK_API, headers=headers, data={"url": url})
            if submit_resp.status_code != 200:
                return "Unknown"

            import time
            time.sleep(3)

            response = requests.get(f"{PHISHING_CHECK_API}/{url_id}", headers=headers)

        if response.status_code != 200:
            return "Unknown"

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0:
            return "Unsafe"
        elif stats.get("harmless", 0) > 0 or stats.get("undetected", 0) > 0:
            return "Safe"
        else:
            return "Unknown"
    except Exception:
        return "Unknown"

# Example: check if domain has MX record
def has_valid_mx_record(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except:
        return False

# **IMPORTANT: Add this endpoint for email scan**

@router.post("/scan-email", summary="Scan email for phishing risks")
async def scan_email(email: EmailInput):
    results = {"keyword_risk": False, "link_risk": False, "sender_risk": False}

    if any(k in email.subject.lower() or k in email.body.lower() for k in SUSPICIOUS_KEYWORDS):
        results["keyword_risk"] = True

    sender_domain = email.sender.split("@")[-1]
    if not has_valid_mx_record(sender_domain):
        results["sender_risk"] = True

    urls = extract_urls(email.body)
    for url in urls:
        if check_url_safety(url) == "Unsafe":
            results["link_risk"] = True
            break

    status = "Unsafe" if any(results.values()) else "Safe"
    return {"result": status, "details": results, "found_urls": urls}
