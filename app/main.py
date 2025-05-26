from fastapi import FastAPI
from app.routes import scan_url, email, info 
from app.database import Base, engine
from fastapi.middleware.cors import CORSMiddleware
print("🚀 Starting FastAPI app...")

app = FastAPI(
    title="Phisher API",
    description="Detect phishing in emails and URLs.",
    version="1.0.0"
)

@app.get("/")
def read_root():
    return {"message": "Welcome to Phisher API. Go to /docs to use the API."}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://phisherr.netlify.app/"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
#  Initialize database tables
Base.metadata.create_all(bind=engine)

#  Include routers
app.include_router(scan_url.router)
app.include_router(email.router) 

 #  This ensures /scan-email appears
app.include_router(info.router) 