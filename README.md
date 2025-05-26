# Phisher - Phishing Detection Backend

This is a FastAPI backend for detecting phishing websites and emails. It also provides cybersecurity tips and legal policies.

## 🚀 Features

-  Scan URLs for phishing threats using VirusTotal, Google Safe Browsing, and PhishTank

-  Analyze phishing emails (basic logic)

-  Display cybersecurity tips

-  Show Privacy Policy and Terms & Conditions

## 🗂️ Project Structure

phisher/
├── app/
│ ├── init.py
│ ├── main.py          # FastAPI entry point
│ ├── models.py        # SQLAlchemy models
│ ├── schemas.py       # Pydantic schemas
│ ├── database.py      # DB setup and connection
│ ├── scan_url.py      # URL scanner endpoint
│ ├── email.py         # Email analyzer endpoint
│ ├── info.py          # Cyber tips, privacy, terms
├── phisher.db         # SQLite database file
├── .env               # Environment variables
├── README.md          # Project documentation
├── requirements.txt   # Python dependencies

shell
Copy code

## 🛠️ How to Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
2. Run the app

bash
Copy code
uvicorn app.main:app --reload

3. Test in browser
Go to: http://127.0.0.1:8000/docs

⚙️ Environment Variables
Create a .env file in your root folder and add:

ini
Copy code
VT_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_KEY=your_google_key
DATABASE_URL=sqlite:///./phisher.db

Security
CORS enabled for cross-origin requests

Add frontend domain in main.py:

python
Copy code
allow_origins=["https://phisherr.netlify.app/"]

📁 Database
SQLite is used. Data is stored in phisher.db.

You can inspect it later with tools like DB Browser for SQLite.




Made with ❤️ for secure browsing.












