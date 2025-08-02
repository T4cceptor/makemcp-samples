import logging
import os
from fastapi import FastAPI, HTTPException, Query, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlmodel import SQLModel, Field, Session, create_engine, select
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv
from jwcrypto import jwk
import json

# Load .env file at startup
load_dotenv()

# Auth settings
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "false").lower() == "true"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_KEY_TYPE = os.getenv("JWT_KEY_TYPE", "hmac")  # hmac or rsa
JWT_ALGORITHM = "RS256" if JWT_KEY_TYPE == "rsa" else "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
JWT_KEY_ID = os.getenv("JWT_KEY_ID", "server-key-1")

# Default user settings
DEFAULT_USER_NAME = os.getenv("DEFAULT_USER_NAME", "John Wood")
DEFAULT_USER_EMAIL = os.getenv("DEFAULT_USER_EMAIL", "jw@awesome.com")
DEFAULT_USER_PASSWORD = os.getenv("DEFAULT_USER_PASSWORD", "defaultpassword123")

# RSA key management
_rsa_private_key: Optional[jwk.JWK] = None
_rsa_public_key: Optional[jwk.JWK] = None

def load_rsa_private_key() -> jwk.JWK:
    """Load RSA private key from .env file"""
    global _rsa_private_key
    if _rsa_private_key is None:
        private_key_pem: Optional[str] = os.getenv("JWT_RSA_PRIVATE_KEY")
        if not private_key_pem:
            raise ValueError("JWT_RSA_PRIVATE_KEY not found in environment")
        _rsa_private_key = jwk.JWK.from_pem(private_key_pem.encode())
    return _rsa_private_key

def get_rsa_public_key() -> jwk.JWK:
    """Get RSA public key derived from private key"""
    global _rsa_public_key
    if _rsa_public_key is None:
        private_key: jwk.JWK = load_rsa_private_key()
        # Try different methods to get public key from jwcrypto
        try:
            _rsa_public_key = jwk.JWK.from_json(private_key.export_public())
        except AttributeError:
            # Alternative method for jwcrypto
            _rsa_public_key = jwk.JWK.from_json(private_key.export_private())
    return _rsa_public_key

def get_public_key_jwk() -> Dict[str, Any]:
    """Get public key in JWK format for JWKS endpoint"""
    private_key: jwk.JWK = load_rsa_private_key()
    # Extract public key as dict directly from private key
    private_key_dict: Dict[str, Any] = json.loads(private_key.export_public())
    
    # Create public key JWK dict
    jwk_dict: Dict[str, Any] = {
        "kty": private_key_dict["kty"],
        "n": private_key_dict["n"],
        "e": private_key_dict["e"],
        "kid": JWT_KEY_ID,
        "use": "sig",
        "alg": "RS256", 
        "key_ops": ["verify"]
    }
    return jwk_dict

def generate_sample_rsa_key() -> str:
    """Helper to generate RSA key for .env file setup"""
    key: jwk.JWK = jwk.JWK.generate(kty='RSA', size=2048)
    pem_bytes: bytes = key.export_to_pem(private_key=True, password=None)
    return pem_bytes.decode()

app = FastAPI()
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
    last_login: datetime | None = Field(default=None)

class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"

# Auth utility functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    if JWT_KEY_TYPE == "rsa":
        # Use RSA private key
        private_key = load_rsa_private_key()
        key_pem = private_key.export_to_pem(private_key=True, password=None)
        return jwt.encode(
            to_encode, 
            key_pem, 
            algorithm="RS256",
            headers={"kid": JWT_KEY_ID}
        )
    else:
        # Use existing HMAC method
        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")

def get_user_by_email_util(session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()

def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = get_user_by_email_util(session, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, echo=True)

# JWT validation middleware
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
        if JWT_KEY_TYPE == "rsa":
            # Use RSA public key for verification
            private_key = load_rsa_private_key()
            # Export public key in PEM format for python-jose
            public_key_pem = private_key.export_to_pem(private_key=False, password=None)
            payload = jwt.decode(credentials.credentials, public_key_pem, algorithms=["RS256"])
        else:
            # Use existing HMAC method
            payload = jwt.decode(credentials.credentials, JWT_SECRET_KEY, algorithms=["HS256"])
            
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
        user = get_user_by_email_util(session, email)
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

@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        if len(users) == 0:
            # Create default user with hashed password
            hashed_password = hash_password(DEFAULT_USER_PASSWORD)
            user = User(
                name=DEFAULT_USER_NAME, 
                email=DEFAULT_USER_EMAIL,
                hashed_password=hashed_password
            )
            session.add(user)
            session.commit()
            logging.info(f"Default user created: {user.email}")

# Auth endpoints
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
        user.last_login = datetime.now()
        session.add(user)
        session.commit()
        
        # Create JWT token
        access_token = create_access_token(data={"sub": user.email})
        return Token(access_token=access_token)

@app.get("/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)

@app.get("/.well-known/jwks.json")
def get_jwks():
    """Return JSON Web Key Set for JWT verification"""
    if JWT_KEY_TYPE != "rsa":
        raise HTTPException(
            status_code=404, 
            detail="JWKS not available with HMAC keys"
        )
    
    try:
        jwk_dict = get_public_key_jwk()
        return {"keys": [jwk_dict]}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating JWKS: {str(e)}")

@app.get("/")
def read_root():
    """
    Root endpoint.
    Returns a welcome message from the FastAPI server.
    """
    return {"message": "Hello from FastAPI!"}

@app.get("/users", response_model=List[UserResponse])
def list_users(current_user: User = Depends(get_current_user)):
    """
    Retrieve a list of all users in the database.
    Returns:
        List[UserResponse]: A list of user objects.
    """
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        return [UserResponse.model_validate(user) for user in users]

@app.post("/users", response_model=UserResponse)
def create_user(user: UserCreate):
    """
    Create a new user in the database (registration).
    Args:
        user (UserCreate): The user data with password.
    Returns:
        UserResponse: The created user object.
    """
    with Session(engine) as session:
        # Check if user exists
        if get_user_by_email_util(session, user.email):
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user with hashed password
        hashed_password = hash_password(user.password)
        db_user = User(
            name=user.name,
            email=user.email,
            hashed_password=hashed_password
        )
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return UserResponse.model_validate(db_user)

@app.get("/users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int, current_user: User = Depends(get_current_user)):
    """
    Retrieve a user by their unique ID.
    Args:
        user_id (int): The ID of the user to retrieve.
    Returns:
        UserResponse: The user object if found.
    Raises:
        HTTPException: If the user is not found.
    """
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return UserResponse.model_validate(user)

@app.get("/users/by_email/", response_model=UserResponse)
def get_user_by_email(email: str = Query(...), current_user: User = Depends(get_current_user)):
    """
    Retrieve a user by their email address.
    Args:
        email (str): The email address to search for.
    Returns:
        UserResponse: The user object if found.
    Raises:
        HTTPException: If the user is not found.
    """
    with Session(engine) as session:
        statement = select(User).where(User.email == email)
        user = session.exec(statement).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return UserResponse.model_validate(user)

@app.patch("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: int, name: Optional[str] = None, email: Optional[str] = None, current_user: User = Depends(get_current_user)):
    """
    Update a user's name and/or email by their ID.
    Args:
        user_id (int): The ID of the user to update.
        name (str, optional): The new name for the user.
        email (str, optional): The new email for the user.
    Returns:
        UserResponse: The updated user object.
    Raises:
        HTTPException: If the user is not found.
    """
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if name:
            user.name = name
        if email:
            user.email = email
        session.add(user)
        session.commit()
        session.refresh(user)
        return UserResponse.model_validate(user)

@app.delete("/users/{user_id}")
def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    """
    Delete a user by their unique ID.
    Args:
        user_id (int): The ID of the user to delete.
    Returns:
        dict: A confirmation message if deletion is successful.
    Raises:
        HTTPException: If the user is not found.
    """
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        session.delete(user)
        session.commit()
        return {"ok": True}
