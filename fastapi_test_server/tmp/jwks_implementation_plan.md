# JWKS (JSON Web Key Set) Implementation Plan

## Overview
Currently, the FastAPI server uses HMAC-SHA256 (HS256) with a symmetric secret key for JWT signing. To enable JWKS functionality for testing MCP server integration with OpenAPI specs, we need to add RSA-SHA256 (RS256) support with asymmetric keys so external tools can verify JWT signatures using the public key.

## Current State
- **Algorithm**: HS256 (HMAC with SHA-256)
- **Key Type**: Symmetric secret key (`JWT_SECRET_KEY`)
- **Verification**: Requires shared secret key
- **JWKS**: Not available

## Target State
- **Algorithm**: RS256 (RSA with SHA-256)
- **Key Type**: RSA public/private key pair
- **Verification**: Public key can be shared via JWKS endpoint
- **JWKS**: Available at `/.well-known/jwks.json`

## Implementation Steps

### 1. Dependencies
Add required packages:
- `python-dotenv>=1.0.0` - For .env file management
- `jwcrypto>=1.5.0` - For RSA key generation and JWKS formatting (better JOSE support than python-jose)
- Keep existing `python-jose[cryptography]` for backward compatibility

### 2. Key Management Strategy
**Fixed Configuration Approach**
- Store RSA private key in `.env` file in server directory
- Load private key at runtime using python-dotenv
- Derive public key from private key
- Persistent and version-controlled (with proper .gitignore)
- Simple for both development and production

### 3. .env File Configuration
Create `.env` file in server directory:
```bash
# Auth configuration
AUTH_ENABLED=false
JWT_EXPIRE_MINUTES=30

# Key management (choose one)
JWT_KEY_TYPE=hmac              # Options: hmac, rsa

# HMAC Configuration (default, existing)
JWT_SECRET_KEY=your-secret-key-change-in-production

# RSA Configuration (for JWKS support)
JWT_KEY_ID=server-key-1
JWT_RSA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----"

# Default user settings
DEFAULT_USER_NAME=John Wood
DEFAULT_USER_EMAIL=jw@awesome.com
DEFAULT_USER_PASSWORD=defaultpassword123
```

### 4. Code Changes

#### 4.1 Environment Loading & Key Management
```python
from dotenv import load_dotenv
from jwcrypto import jwk
import os

# Load .env file at startup
load_dotenv()

# Key management functions
def load_rsa_private_key():
    """Load RSA private key from .env file"""
    private_key_pem = os.getenv("JWT_RSA_PRIVATE_KEY")
    return jwk.JWK.from_pem(private_key_pem.encode())
    
def get_public_key_jwk():
    """Extract public key and format as JWK"""
    private_key = load_rsa_private_key()
    public_key = private_key.get_public_key()
    return public_key.export_public()
    
def generate_sample_rsa_key():
    """Helper to generate RSA key for .env file setup"""
    key = jwk.JWK.generate(kty='RSA', size=2048)
    return key.export_to_pem(private_key=True)
```

#### 4.2 JWT Functions Updates
```python
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    jwt_key_type = os.getenv("JWT_KEY_TYPE", "hmac")
    
    if jwt_key_type == "rsa":
        # Use RSA private key
        private_key = load_rsa_private_key()
        key_id = os.getenv("JWT_KEY_ID", "server-key-1")
        return jwt.encode(
            to_encode, 
            private_key.export_to_pem(private_key=True), 
            algorithm="RS256",
            headers={"kid": key_id}
        )
    else:
        # Use existing HMAC method
        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")
    
def verify_jwt_token(token: str):
    jwt_key_type = os.getenv("JWT_KEY_TYPE", "hmac")
    
    if jwt_key_type == "rsa":
        # Use RSA public key
        private_key = load_rsa_private_key()
        public_key = private_key.get_public_key()
        return jwt.decode(
            token, 
            public_key.export_to_pem(), 
            algorithms=["RS256"]
        )
    else:
        # Use existing HMAC method
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
```

#### 4.3 JWKS Endpoint
```python
@app.get("/.well-known/jwks.json")
def get_jwks():
    """Return JSON Web Key Set for JWT verification"""
    jwt_key_type = os.getenv("JWT_KEY_TYPE", "hmac")
    
    if jwt_key_type != "rsa":
        raise HTTPException(
            status_code=404, 
            detail="JWKS not available with HMAC keys"
        )
    
    try:
        private_key = load_rsa_private_key()
        public_key = private_key.get_public_key()
        key_id = os.getenv("JWT_KEY_ID", "server-key-1")
        
        # Format as JWKS
        jwk_dict = public_key.export_public(as_dict=True)
        jwk_dict.update({
            "kid": key_id,
            "use": "sig",
            "alg": "RS256",
            "key_ops": ["verify"]
        })
        
        return {"keys": [jwk_dict]}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error generating JWKS")
```

### 5. Backward Compatibility
- Default to existing HMAC implementation (`JWT_KEY_TYPE=hmac`)
- Existing environment variables continue to work
- No breaking changes to existing deployments

### 6. Testing Considerations
- RSA keys stored in `.env` for easy testing setup
- Fixed key IDs for consistent test scenarios
- JWKS endpoint availability for MCP server integration testing
- JWT verification compatibility with various testing tools

### 7. Testing Strategy
- Test both HMAC and RSA modes
- Verify JWKS endpoint returns valid JWK format
- Test JWT verification with external tools
- Validate backward compatibility

### 8. Usage Examples

#### Setup .env File for RSA
```bash
# Create .env file with RSA configuration
cp .env.example .env
# Edit .env and set JWT_KEY_TYPE=rsa
# Add your RSA private key to JWT_RSA_PRIVATE_KEY
```

#### Development with RSA Keys
```bash
make run-auth
# Reads from .env file, uses RSA if JWT_KEY_TYPE=rsa
# JWKS available at /.well-known/jwks.json
```

#### Backward Compatible (Current behavior)
```bash
# .env file with JWT_KEY_TYPE=hmac (or not set)
make run-auth
# Uses existing HMAC implementation
# No JWKS endpoint available (returns 404)
```

#### Key Generation Helper
```bash
# Add a Make target to generate RSA keys
make generate-rsa-key
# Outputs RSA private key for .env file
```

### 9. JWKS Response Format
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "key_ops": ["verify"],
      "alg": "RS256",
      "kid": "server-key-1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### 10. Implementation Priority
1. **High**: Key management and JWT function updates
2. **High**: JWKS endpoint implementation  
3. **Medium**: Environment variable configuration
4. **Medium**: Backward compatibility testing
5. **Low**: Documentation and examples

## Benefits for MCP Testing
- **Interoperability**: MCP servers can verify JWTs without shared secrets
- **Testing Flexibility**: Public key cryptography enables external JWT verification
- **Standards Compliance**: Follows OAuth 2.0 and OpenID Connect standards for realistic testing
- **Tool Integration**: Compatible with JWT verification libraries and API testing tools
- **Zero Disruption**: Backward compatible migration path for existing test scenarios

## File Structure After Implementation
```
fastapi_test_server/
├── main.py                    # Updated with RSA and .env support
├── requirements.txt           # Added python-dotenv, jwcrypto
├── Makefile                   # Updated with key generation helper
├── .env                       # Environment configuration (not in git)
├── .env.example              # Template for .env file
├── .gitignore                # Excludes .env file
└── tmp/
    ├── jwks_implementation_plan.md
    └── jwt_auth_implementation.md
```

## Key Advantages of This Approach

### 1. **Fixed Configuration Management**
- All configuration in one `.env` file
- Easy to manage different environments
- No key generation complexity at runtime
- Clear separation of config from code

### 2. **Superior JOSE Library Support**
- `jwcrypto` provides better JWKS support than `python-jose`
- Better RSA key handling and JWK formatting
- More comprehensive JOSE specification compliance

### 3. **Development-Friendly**
- Simple key setup process
- Persistent keys across restarts
- Easy debugging with fixed keys
- Make targets for common operations

### 4. **Test-Environment Optimized**
- Simple key storage in `.env` files for easy test setup
- Proper .gitignore configuration to avoid committing test keys
- Easy configuration switching for different test scenarios
- No runtime key generation overhead during testing