from pydantic import BaseModel

class URLScanCreate(BaseModel):
    url: str

class URLScanOut(BaseModel):
    id: int
    url: str
    result: str

class Config:
    from_attributes = True
