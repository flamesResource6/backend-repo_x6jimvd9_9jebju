"""
Database Schemas for Comic App

Pydantic models define MongoDB collections. Class name lowercased is the
collection name.
"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Users
class User(BaseModel):
    email: EmailStr
    password_hash: str
    display_name: str = Field(..., max_length=64)
    avatar_url: Optional[str] = None
    is_active: bool = True

# Comics
class Comic(BaseModel):
    title: str
    author: str
    genres: List[str] = []
    synopsis: Optional[str] = None
    cover_url: Optional[str] = None
    rating: float = 0.0

# Chapters
class Chapter(BaseModel):
    comic_id: str
    number: int
    title: Optional[str] = None
    images: List[str] = []  # URLs to page images in reading order
    released_at: Optional[datetime] = None

# Bookmarks
class Bookmark(BaseModel):
    user_id: str
    comic_id: str
    chapter_number: Optional[int] = None

# Reading history
class History(BaseModel):
    user_id: str
    comic_id: str
    chapter_number: int
    last_read_at: datetime

