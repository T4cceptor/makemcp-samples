# FastAPI JWT Authentication Implementation Guide

## Overview
This guide outlines adding JWT-based bearer token authentication to the FastAPI server with toggleable auth and database-backed user management.

## 1. Dependencies & Configuration

### Update requirements.txt
```
fastapi>=0.115.13
sqlmodel>=0.0.24
uvicorn>=0.34.3
python-jose[cryptography]>=3.3.0
passlib[bcrypt]>=1.7.4
python-multipart>=0.0.5
```

### Environment Configuration
Add to main.py:
```python
import os
from datetime import timedelta

# Auth settings
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() == "true"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
```

## 2. Enhanced User Model

Replace existing User model in main.py:
```python
from sqlmodel import SQLModel, Field
from datetime import datetime
from typing import Optional

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = Field(default=True)
    created_date: datetime = Field(default_factory=datetime.utcnow)
    last_login: datetime | None = Field(default=None)

# Pydantic models for API
class UserCreate(SQLModel):
    name: str
    email: str
    password: str

class UserLogin(SQLModel):
    email: str
    password: str

class UserResponse(SQLModel):
    id: int
    name: str
    email: str
    is_active: bool
    created_date: datetime

class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"
```

## 3. Auth Utilities

Add to main.py:
```python
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def get_user_by_email(session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = get_user_by_email(session, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user
```

## 4. Auth Endpoints

Add new authentication routes:
```python
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)

@app.post("/auth/register", response_model=UserResponse)
def register_user(user_data: UserCreate):
    with Session(engine) as session:
        # Check if user exists
        if get_user_by_email(session, user_data.email):
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        hashed_password = hash_password(user_data.password)
        user = User(
            name=user_data.name,
            email=user_data.email,
            hashed_password=hashed_password
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return UserResponse.from_orm(user)

@app.post("/auth/login", response_model=Token)
def login_user(user_credentials: UserLogin):
    with Session(engine) as session:
        user = authenticate_user(session, user_credentials.email, user_credentials.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        
        # Update last login
        user.last_login = datetime.utcnow()
        session.add(user)
        session.commit()
        
        # Create JWT token
        access_token = create_access_token(data={"sub": user.email})
        return Token(access_token=access_token)

@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse.from_orm(current_user)
```

## 5. JWT Validation Middleware

Add authentication dependency:
```python
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    # Skip auth if disabled
    if not AUTH_ENABLED:
        # Return a default user or skip validation
        with Session(engine) as session:
            return session.exec(select(User)).first()  # Return any user for testing
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required"
        )
    
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    with Session(engine) as session:
        user = get_user_by_email(session, email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user"
            )
        return user

# Optional dependency for when auth is disabled
def get_current_user_optional(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User | None:
    if not AUTH_ENABLED:
        return None
    return get_current_user(credentials)
```

## 6. Protected Endpoints

Update existing user endpoints to require authentication:
```python
@app.get("/users", response_model=List[UserResponse])
def list_users(current_user: User = Depends(get_current_user)):
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        return [UserResponse.from_orm(user) for user in users]

@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate, current_user: User = Depends(get_current_user)):
    # Only for admin users or when auth is disabled
    hashed_password = hash_password(user.password)
    with Session(engine) as session:
        db_user = User(
            name=user.name,
            email=user.email,
            hashed_password=hashed_password
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return UserResponse.from_orm(db_user)

# Add Depends(get_current_user) to all other user endpoints:
# - get_user_by_id
# - get_user_by_email  
# - update_user
# - delete_user
```

## 7. Startup Configuration

Update Makefile:
```makefile
VENV=.venv
VENV_ACTIVATE=$(VENV)/bin/activate

.PHONY: venv install run run-auth clean

venv:
	python3 -m venv $(VENV)

install: venv
	. $(VENV_ACTIVATE) && pip install -r requirements.txt

run:
	. $(VENV_ACTIVATE) && uvicorn main:app --reload --host localhost --port 8081

run-auth:
	. $(VENV_ACTIVATE) && AUTH_ENABLED=true JWT_SECRET_KEY=your-super-secret-key uvicorn main:app --reload --host localhost --port 8081

clean:
	rm -rf $(VENV)
	rm -f test.db
```

Update startup event to create default user with password:
```python
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        if len(users) == 0:
            # Create default user with hashed password
            hashed_password = hash_password("defaultpassword123")
            user = User(
                name="John Wood", 
                email="jw@awesome.com",
                hashed_password=hashed_password
            )
            session.add(user)
            session.commit()
            logging.info(f"Default user created: {user.email}")
```

## 8. Usage Flow

### Without Auth (default)
```bash
make run
# All endpoints accessible without tokens
```

### With Auth
```bash
make run-auth
# 1. Register: POST /auth/register
# 2. Login: POST /auth/login → get JWT token
# 3. Use token: Authorization: Bearer <token>
```

### Example API calls

**Register new user:**
```bash
curl -X POST "http://localhost:8081/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "email": "test@example.com", "password": "password123"}'
```

**Login:**
```bash
curl -X POST "http://localhost:8081/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'
```

**Use protected endpoint:**
```bash
curl -X GET "http://localhost:8081/users" \
  -H "Authorization: Bearer <jwt-token>"
```

**Default user credentials (for testing):**
- Email: `jw@awesome.com`
- Password: `defaultpassword123`

## Features Provided

- **Toggle-able auth** via environment variables
- **JWT-based authentication** with proper token validation
- **User registration/login** with password hashing
- **Database-backed user management** 
- **Protected API endpoints** with dependency injection
- **Simple startup**: `make run` vs `make run-auth`
- **Secure password storage** using bcrypt
- **Token expiration** configurable via environment
- **User session tracking** with last_login field