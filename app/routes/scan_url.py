import asyncio
import os
import base64
import urllib.parse
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import httpx

from app.models import URLScan
from app.database import get_db
from app.schemas import URLScanCreate, URLScanOut

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")  # Optional for advanced use

router = APIRouter()

def get_vt_url_id(url: str) -> str:
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    url = urllib.parse.quote(url, safe='')
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return url_id

@router.post("/scan-url", response_model=URLScanOut)
async def scan_url(url_data: URLScanCreate, db: Session = Depends(get_db)):
    url = url_data.url

    existing = db.query(URLScan).filter(URLScan.url == url).first()
    if existing:
        return existing

    vt_result = "Unknown"
    source = "None"

    headers = {"x-apikey": VT_API_KEY}
    vt_base_url = "https://www.virustotal.com/api/v3/urls"

    url_id = get_vt_url_id(url)

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            get_resp = await client.get(f"{vt_base_url}/{url_id}", headers=headers)
            if get_resp.status_code == 200:
                data = get_resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                if malicious > 0:
                    vt_result = "Unsafe"
                    source = "VirusTotal"
                elif harmless > 0 or undetected > 0:
                    vt_result = "Safe"
                    source = "VirusTotal"
            elif get_resp.status_code == 404:
                post_resp = await client.post(vt_base_url, json={"url": url}, headers=headers)
                if post_resp.status_code == 200:
                    await asyncio.sleep(5)
                    get_resp2 = await client.get(f"{vt_base_url}/{url_id}", headers=headers)
                    if get_resp2.status_code == 200:
                        data = get_resp2.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        harmless = stats.get("harmless", 0)
                        undetected = stats.get("undetected", 0)
                        if malicious > 0:
                            vt_result = "Unsafe"
                            source = "VirusTotal"
                        elif harmless > 0 or undetected > 0:
                            vt_result = "Safe"
                            source = "VirusTotal"
        except Exception as e:
            print("VirusTotal error:", e)

    if vt_result == "Unknown" and GOOGLE_SAFE_BROWSING_KEY:
        try:
            gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"
            payload = {
                "client": {"clientId": "phisher-app", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            async with httpx.AsyncClient() as client:
                response = await client.post(gsb_url, json=payload)
                if response.status_code == 200 and response.json().get("matches"):
                    vt_result = "Unsafe"
                    source = "Google Safe Browsing"
        except Exception as e:
            print("Google Safe Browsing error:", e)

    if vt_result == "Unknown":
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                openphish_resp = await client.get("https://openphish.com/feed.txt")
                if openphish_resp.status_code == 200:
                    if url in openphish_resp.text:
                        vt_result = "Unsafe"
                        source = "OpenPhish"
        except Exception as e:
            print("OpenPhish error:", e)

    if vt_result == "Unknown":
        try:
            phishtank_resp = await client.get("http://data.phishtank.com/data/online-valid.json")
            if phishtank_resp.status_code == 200:
                results = phishtank_resp.json()
                for item in results:
                    if item.get("url") == url:
                        vt_result = "Unsafe"
                        source = "PhishTank"
                        break
        except Exception as e:
            print("PhishTank error:", e)

    scan = URLScan(url=url, result=vt_result)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan
