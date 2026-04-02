# model.py

def extract_features(url):
    return {
        "length": len(url),
        "has_https": url.startswith("https"),
        "dots": url.count('.'),
        "has_suspicious_word": any(word in url.lower() for word in ["login", "verify", "bank", "secure", "update"])
    }

def predict_url(url):
    features = extract_features(url)

    score = 0

    if features["length"] > 100:
        score += 1
    if not features["has_https"]:
        score += 1
    if features["dots"] > 5:
        score += 1
    if features["has_suspicious_word"]:
        score += 1

    if score >= 3:
        return "🚨 Malicious Website"
    elif score == 2:
        return "⚠️ Suspicious Website"
    else:
        return "✅ Safe Website"