"""
Example usage of security headers middleware.
"""

from fastapi import FastAPI
from shared.security.headers import (
    SecurityHeadersConfig, 
    SecurityHeadersMiddleware,
    create_production_security_config,
    create_development_security_config,
    CSPDirective,
    ReferrerPolicy,
    SameSitePolicy
)

# Create FastAPI app
app = FastAPI(title="Security Headers Example")

# Example 1: Production configuration
production_config = create_production_security_config()
production_middleware = SecurityHeadersMiddleware(production_config)
app.add_middleware(type(production_middleware), config=production_config)

# Example 2: Development configuration
# development_config = create_development_security_config()
# development_middleware = SecurityHeadersMiddleware(development_config)
# app.add_middleware(type(development_middleware), config=development_config)

# Example 3: Custom configuration
custom_config = SecurityHeadersConfig(
    # Custom CSP for a web app that uses external APIs
    csp_directives={
        CSPDirective.DEFAULT_SRC: ["'self'"],
        CSPDirective.SCRIPT_SRC: ["'self'", "https://cdn.jsdelivr.net"],
        CSPDirective.STYLE_SRC: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        CSPDirective.IMG_SRC: ["'self'", "data:", "https:"],
        CSPDirective.CONNECT_SRC: ["'self'", "https://api.example.com"],
        CSPDirective.FONT_SRC: ["'self'", "https://fonts.gstatic.com"],
        CSPDirective.OBJECT_SRC: ["'none'"],
        CSPDirective.FRAME_ANCESTORS: ["'none'"],
        CSPDirective.BASE_URI: ["'self'"]
    },
    
    # CORS configuration for API endpoints
    api_cors_origins=["https://webapp.example.com", "https://mobile.example.com"],
    api_cors_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    api_cors_headers=["Content-Type", "Authorization", "X-Requested-With", "X-API-Key"],
    api_cors_credentials=True,
    
    # Custom headers
    custom_headers={
        "X-Service-Name": "MCP Security Platform",
        "X-API-Version": "v1.0.0"
    }
)

# Example routes
@app.get("/")
async def root():
    """Main page - will get web security headers."""
    return {"message": "Hello World"}

@app.get("/api/health")
async def api_health():
    """API endpoint - will get API-specific headers."""
    return {"status": "healthy"}

@app.get("/api/data")
async def api_data():
    """API endpoint with CORS headers."""
    return {"data": [1, 2, 3, 4, 5]}

@app.post("/api/upload")
async def api_upload():
    """Upload endpoint with strict security headers."""
    return {"uploaded": True}

if __name__ == "__main__":
    import uvicorn
    
    print("Starting server with security headers...")
    print("Production config includes:")
    print("- Strict Content Security Policy")
    print("- HSTS with 2-year max-age and preload")
    print("- X-Frame-Options: DENY")
    print("- Secure cookie settings")
    print("- Cross-origin isolation policies")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)