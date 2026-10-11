from datetime import datetime
import ipaddress
import re
import socket
from urllib.parse import urlparse
import tldextract
import whois

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# 1. Initialize Rate Limiter (Max 10 requests per minute per IP to prevent DoS)
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Secure Phishing URL Threat Intel")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 2. Hardened Cross-Origin (CORS) Policy - Block wildcards (*) in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"], 
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# 3. Secure HTTP Response Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"  # Prevents Clickjacking
    response.headers["X-Content-Type-Options"] = "nosniff"  # Prevents MIME sniffing
    response.headers["X-XSS-Protection"] = "1; mode=block"  # Hardens XSS block rules
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    return response

TRUSTED_DOMAINS = {"google.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com", "paypal.com", "github.com"}
SUSPICIOUS_KEYWORDS = ["verify", "secure", "update", "login", "signin", "banking", "account", "wallet", "crypto", "free", "gift", "bonus", "support", "service-update"]

# Sanitize input size lengths to prevent payload injection overflows
class URLRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="Target analysis URL string")

def is_private_ip(ip_str: str) -> bool:
    """Helper to detect and block SSRF requests targeting local or private networks."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def check_domain_details(domain: str) -> tuple:
    ip_address, creation_date = None, None
    try:
        # Resolve target DNS string
        resolved_ip = socket.gethostbyname(domain)
        # SSRF Mitigation: Refuse to inspect internal corporate nodes
        if is_private_ip(resolved_ip):
            return "BLOCKED_INTERNAL_IP", None
        ip_address = resolved_ip
    except Exception: 
        pass

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date if isinstance(w.creation_date, list) else w.creation_date
    except Exception: 
        pass

    return ip_address, creation_date

def analyze_url(url: str) -> dict:
    url = url.strip()
    
    # Simple input validation filtering out script injection characters
    if any(char in url for char in ['<', '>', '"', "'", '`']):
        return {"error": "Malicious payload indicators detected inside URL string."}

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        extracted = tldextract.extract(url)
    except Exception as e:
        return {"error": f"Invalid URL structure: {e}"}

    domain = f"{extracted.domain}.{extracted.suffix}".lower()
    subdomain = extracted.subdomain.lower()
    indicators, risk_score, server_ip, age_str = [], 0, "N/A", "Unknown"

    # Absolute SSRF Check for raw host IP strings
    is_ip = bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', extracted.domain))
    if is_ip and is_private_ip(extracted.domain):
        return {"error": "Security Restriction: Direct access to local/private addresses is prohibited."}

    if domain in TRUSTED_DOMAINS:
        try: 
            resolved_ip = socket.gethostbyname(domain)
            if is_private_ip(resolved_ip): return {"error": "Access to local infrastructure denied."}
        except Exception: 
            resolved_ip = "N/A"
        return {"url": url, "verdict": "SAFE", "risk_score": 0, "ip": resolved_ip, "age": "Established Brand", "indicators": ["Matches a known highly trusted domain."]}

    if not is_ip:
        server_ip, creation_date = check_domain_details(domain)
        
        if server_ip == "BLOCKED_INTERNAL_IP":
            return {"error": "Access to internal infrastructure ranges is blocked for safety."}
            
        if not server_ip:
            indicators.append(f"Domain '{domain}' does not resolve to an active IP address.")
            risk_score += 55
            server_ip = "INACTIVE (DNS Failed)"
            
        if creation_date and isinstance(creation_date, datetime):
            days_old = (datetime.now() - creation_date).days
            age_str = f"{days_old} days old (Created: {creation_date.strftime('%Y-%m-%d')})"
            if days_old < 180:
                indicators.append(f"Domain is very young ({days_old} days old).")
                risk_score += 45
        else: 
            age_str = "Could not pull registration data"
    else:
        server_ip = extracted.domain
        age_str = "Skipped (Raw IP)"

    if is_ip: 
        indicators.append("Uses a raw IP address."); risk_score += 40
    found_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_kws: 
        indicators.append(f"Contains keywords: {found_kws}"); risk_score += len(found_kws) * 15
    
    for t in TRUSTED_DOMAINS:
        tb = t.split('.')[0]
        if tb in subdomain and tb != extracted.domain: 
            indicators.append(f"Impersonates brand '{tb}' in subdomain."); risk_score += 35
            
    if len([p for p in subdomain.split('.') if p]) >= 3: 
        indicators.append("Excessive subdomains."); risk_score += 20
    if "-" in extracted.domain: 
        indicators.append("Domain contains a hyphen."); risk_score += 15
    if len(url) > 75: 
        indicators.append("URL is unusually long."); risk_score += 10

    verdict = "HIGH RISK" if risk_score >= 50 else ("MODERATE RISK" if risk_score >= 20 else "LOW RISK")
    return {"url": url, "verdict": verdict, "risk_score": min(risk_score, 100), "ip": server_ip, "age": age_str, "indicators": indicators or ["No obvious signs found."]}

# 4. Enforce strict rate limits on state-changing API endpoints
@app.post("/api/analyze")
@limiter.limit("10/minute")
def api_analyze(payload: URLRequest, request: Request):
    result = analyze_url(payload.url)
    if "error" in result: 
        raise HTTPException(status_code=400, detail=result["error"])
    return result

app.mount("/", StaticFiles(directory="ui", html=True), name="ui")

if __name__ == "__main__":
    import uvicorn
    import os

    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 Launching production threat intel cluster on port {port}...")
    uvicorn.run("main:app", host="0.0.0.0", port=port)
