from fastapi import APIRouter

router = APIRouter()

@router.get("/cyber-tips")
async def cyber_tips():
    return {
        "tips": [
            "Never click unknown links or attachments.",
            "Use strong, unique passwords.",
            "Enable two-factor authentication.",
            "Keep software and antivirus up to date.",
            "Verify sender emails before responding."
        ]
    }

@router.get("/terms")
async def terms_and_conditions():
    return {
        "terms": "By using this app, you agree to use it for lawful and non-malicious purposes..."
    }

@router.get("/privacy")
async def privacy_policy():
    return {
        "privacy": "We respect your privacy and do not store personal data beyond necessary logs..."
    }
