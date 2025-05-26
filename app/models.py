from sqlalchemy import Column, Integer, String
from app.database import Base

class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    result = Column(String)
