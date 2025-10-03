from pydantic import BaseModel, EmailStr
from typing import Optional, List, Any


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: str  # Changed from EmailStr to str to match frontend
    password: str
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "test@example.com",
                "password": "password123"
            }
        }
    }


class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr

    model_config = {"from_attributes": True}


class QueryRequest(BaseModel):
    query: str
    language: Optional[str] = 'en'
    # Allow extra filter fields sent by the frontend (dateFrom, dateTo, etc.)
    model_config = {"extra": "allow"}


class ChatMessage(BaseModel):
    query: str
    answer: str
    sources: Optional[List[Any]] = []
