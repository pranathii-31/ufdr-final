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

    class Config:
        orm_mode = True


class QueryRequest(BaseModel):
    query: str
    language: Optional[str] = 'en'


class ChatMessage(BaseModel):
    query: str
    answer: str
    sources: Optional[List[Any]] = []
