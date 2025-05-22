from flask import Flask, render_template, request
import os
from urllib.parse import urlparse
import socket

app = Flask(__name__)

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    parsed = urlparse(url)
    features['domain'] = parsed.netloc
    features['scheme'] = parsed.scheme
    features['has_https'] = parsed.scheme == 'https'

    # Check if domain resolves (basic check)
    try:
        socket.gethostbyname(features['domain'])
        features['domain_resolves'] = True
    except:
        features['domain_resolves'] = False

    # Suspicious keyword check
    suspicious_keywords = ["login", "secure", "bank", "account", "update", "verify", "confirm", "webscr", "signin"]
    features['suspicious_keywords_found'] = [kw for kw in suspicious_keywords if kw in url.lower()]

    return features

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url")
    features = extract_features(url)

    phishing_score = 0
    details = []

    # Simple heuristic scoring
    if not features['has_https']:
        phishing_score += 2
        details.append("URL does not use HTTPS.")
    if features['url_length'] > 75:
        phishing_score += 1
        details.append("URL length is unusually long.")
    if not features['domain_resolves']:
        phishing_score += 2
        details.append("Domain does not resolve.")
    if features['suspicious_keywords_found']:
        phishing_score += len(features['suspicious_keywords_found'])
        details.append(f"Suspicious keywords found: {', '.join(features['suspicious_keywords_found'])}")

    is_phishing = phishing_score >= 3

    result = {
        "url": url,
        "is_phishing": is_phishing,
        "score": phishing_score,
        "details": details,
        "features": features
    }
    return render_template("result.html", result=result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
