import os
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-dev-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Comic Reader API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------
# Auth Models
# ------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    display_name: str

class ResetRequest(BaseModel):
    email: EmailStr

# ------------------------
# Utils
# ------------------------
from bson import ObjectId

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user_id(token: str = Depends(oauth2_scheme)) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return user_id
    except JWTError:
        raise credentials_exception

# ------------------------
# Routes: Health
# ------------------------
@app.get("/")
def read_root():
    return {"message": "Comic Reader API running"}

@app.get("/test")
def test_database():
    info = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            info["database"] = "✅ Available"
            info["connection_status"] = "Connected"
            info["collections"] = db.list_collection_names()
    except Exception as e:
        info["database"] = f"⚠️ Error: {str(e)[:80]}"
    return info

# ------------------------
# Auth Endpoints
# ------------------------
@app.post("/auth/register", response_model=Token)
def register(body: RegisterRequest):
    if db is None:
        raise HTTPException(500, "Database not configured")
    existing = db["user"].find_one({"email": body.email})
    if existing:
        raise HTTPException(400, "Email already registered")
    user_doc = {
        "email": body.email,
        "password_hash": hash_password(body.password),
        "display_name": body.display_name,
        "avatar_url": None,
        "is_active": True,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    res = db["user"].insert_one(user_doc)
    token = create_access_token({"sub": str(res.inserted_id)})
    return Token(access_token=token)

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if db is None:
        raise HTTPException(500, "Database not configured")
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(400, "Incorrect email or password")
    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)

@app.post("/auth/request-reset")
def request_reset(body: ResetRequest):
    # In a real app, send email with token. Here we acknowledge.
    return {"message": "If the email exists, a reset link was sent."}

# ------------------------
# Comics Endpoints
# ------------------------
class ComicCreate(BaseModel):
    title: str
    author: str
    genres: List[str] = []
    synopsis: Optional[str] = None
    cover_url: Optional[str] = None
    rating: float = 0.0

class ComicOut(BaseModel):
    id: str
    title: str
    author: str
    genres: List[str]
    synopsis: Optional[str]
    cover_url: Optional[str]
    rating: float

from bson.json_util import dumps

def serialize_doc(doc) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc

@app.get("/comics", response_model=List[ComicOut])
def list_comics(q: Optional[str] = None, genre: Optional[str] = None, limit: int = 20):
    if db is None:
        return []
    filters = {}
    if q:
        filters["title"] = {"$regex": q, "$options": "i"}
    if genre:
        filters["genres"] = genre
    items = list(db["comic"].find(filters).limit(limit))
    return [serialize_doc(x) for x in items]

@app.post("/comics", response_model=ComicOut)
def create_comic(body: ComicCreate, user_id: str = Depends(get_current_user_id)):
    if db is None:
        raise HTTPException(500, "Database not configured")
    doc = body.model_dump()
    doc.update({"created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})
    res = db["comic"].insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_doc(doc)

@app.get("/comics/{comic_id}", response_model=ComicOut)
def get_comic(comic_id: str):
    item = db["comic"].find_one({"_id": ObjectId(comic_id)})
    if not item:
        raise HTTPException(404, "Comic not found")
    return serialize_doc(item)

# Chapters
class ChapterCreate(BaseModel):
    number: int
    title: Optional[str] = None
    images: List[str] = []

class ChapterOut(BaseModel):
    id: str
    comic_id: str
    number: int
    title: Optional[str]
    images: List[str]

@app.get("/comics/{comic_id}/chapters", response_model=List[ChapterOut])
def list_chapters(comic_id: str):
    items = list(db["chapter"].find({"comic_id": comic_id}).sort("number", 1))
    for x in items:
        x["id"] = str(x.pop("_id"))
        x["comic_id"] = comic_id
    return items

@app.post("/comics/{comic_id}/chapters", response_model=ChapterOut)
def create_chapter(comic_id: str, body: ChapterCreate, user_id: str = Depends(get_current_user_id)):
    doc = body.model_dump()
    doc.update({"comic_id": comic_id, "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})
    res = db["chapter"].insert_one(doc)
    doc["_id"] = res.inserted_id
    doc["id"] = str(doc.pop("_id"))
    doc["comic_id"] = comic_id
    return doc

# Bookmarks
class BookmarkOut(BaseModel):
    id: str
    comic_id: str
    chapter_number: Optional[int] = None

@app.get("/me/bookmarks", response_model=List[BookmarkOut])
def get_bookmarks(user_id: str = Depends(get_current_user_id)):
    items = list(db["bookmark"].find({"user_id": user_id}))
    return [{"id": str(x["_id"]), "comic_id": x["comic_id"], "chapter_number": x.get("chapter_number") } for x in items]

class BookmarkCreate(BaseModel):
    comic_id: str
    chapter_number: Optional[int] = None

@app.post("/me/bookmarks", response_model=BookmarkOut)
def add_bookmark(body: BookmarkCreate, user_id: str = Depends(get_current_user_id)):
    doc = {"user_id": user_id, **body.model_dump(), "created_at": datetime.utcnow()}
    res = db["bookmark"].insert_one(doc)
    return {"id": str(res.inserted_id), "comic_id": body.comic_id, "chapter_number": body.chapter_number}

# History
class HistoryOut(BaseModel):
    id: str
    comic_id: str
    chapter_number: int
    last_read_at: datetime

class HistoryCreate(BaseModel):
    comic_id: str
    chapter_number: int

@app.get("/me/history", response_model=List[HistoryOut])
def get_history(user_id: str = Depends(get_current_user_id)):
    items = list(db["history"].find({"user_id": user_id}).sort("last_read_at", -1))
    return [{"id": str(x["_id"]), "comic_id": x["comic_id"], "chapter_number": x["chapter_number"], "last_read_at": x.get("last_read_at") } for x in items]

@app.post("/me/history", response_model=HistoryOut)
def upsert_history(body: HistoryCreate, user_id: str = Depends(get_current_user_id)):
    now = datetime.utcnow()
    result = db["history"].find_one_and_update(
        {"user_id": user_id, "comic_id": body.comic_id},
        {"$set": {"chapter_number": body.chapter_number, "last_read_at": now}, "$setOnInsert": {"created_at": now}},
        upsert=True, return_document=True
    )
    doc = db["history"].find_one({"user_id": user_id, "comic_id": body.comic_id})
    return {"id": str(doc["_id"]), "comic_id": doc["comic_id"], "chapter_number": doc["chapter_number"], "last_read_at": doc.get("last_read_at", now)}

# Simple schema exposure for tooling
@app.get("/schema")
def get_schema_info():
    return {
        "collections": ["user", "comic", "chapter", "bookmark", "history"],
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
