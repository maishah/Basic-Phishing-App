
import pandas as pd
import re
import string
import logging
from datetime import datetime
from bs4 import BeautifulSoup
import joblib
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import nltk
import html

# ─── Security Practice: Secure Logging Setup ────────────────────────────────────
logging.basicConfig(
    filename='app_requests.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)

# Download NLTK resources
nltk.download('stopwords')
nltk.download('wordnet')

# Load Random Forest model and TF-IDF vectorizer
model = joblib.load('phishing_rf_model.pkl')
tfidf = joblib.load('tfidf_vectorizer.pkl') 

# NLP tools
stop_words = set(stopwords.words('english'))
lemmatizer = WordNetLemmatizer()

# Suspicious terms list
suspicious_terms = [
    "urgent", "verify", "login", "click", "password", "confirm", "immediately",
    "limited time", "action required", "suspended", "unauthorized", "security alert",
    "validate", "alert", "compromise", "reset", "credentials", "locked",
    "verify identity", "failure", "warning", "threat", "penalty", "violation",
    "malicious", "phishing", "virus", "breach", "winner", "prize", "reward",
    "congratulations", "claim", "guarantee", "final notice", "act now",
    "bank", "transfer", "balance", "transaction", "credit", "debit", "loan", "wire",
    "funds", "statement", "routing", "swift", "iban", "sort code", "checking", "savings",
    "finance", "financial", "investment", "overdraft", "mortgage", "deposit", "withdrawal",
    "atm", "interest", "fee", "charges", "security code", "card number", "pin", "cvv",
    "issuer", "banking", "online banking"
]

# Preprocessing function
def preprocess_text(text):
    text = BeautifulSoup(text, "html.parser").get_text()
    text = text.lower()
    text = text.translate(str.maketrans('', '', string.punctuation))
    words = text.split()
    words = [lemmatizer.lemmatize(word) for word in words if word not in stop_words]
    return " ".join(words)

# Feature extraction function
def extract_features(text):
    if not isinstance(text, str):
        text = ""

    processed_text = preprocess_text(text)
    tfidf_features = tfidf.transform([processed_text]).toarray()

    url_pattern = re.compile(r'https?://\S+|www\.\S+')
    ip_url_pattern = re.compile(r'https?://\d{1,3}(\.\d{1,3}){3}')

    words = text.split()
    rule_features = [
        len(words),
        len(url_pattern.findall(text)),
        sum(word.lower() in suspicious_terms for word in words),
        int(any(word.lower() in suspicious_terms for word in words if word.lower() in ['bank', 'credit', 'loan'])),
        int('login' in text.lower() or 'sign in' in text.lower()),
        text.count('!'),
        int(bool(ip_url_pattern.search(text))),
        sum(1 for word in words if word.isupper())
    ]

    final_features = list(tfidf_features[0]) + rule_features
    return pd.DataFrame([final_features])

# Highlight suspicious phrases
def highlight_suspicious_terms(text):
    safe_text = html.escape(text)
    sorted_terms = sorted(suspicious_terms, key=len, reverse=True)
    for term in sorted_terms:
        pattern = re.compile(fr'\b({re.escape(term)})\b', re.IGNORECASE)
        safe_text = pattern.sub(r'<mark>\1</mark>', safe_text)
    return safe_text

# Explainability features
def explain_features(features):
    feature_names = tfidf.get_feature_names_out().tolist() + [
        'num_words', 'num_links', 'num_suspicious_words', 'has_bank_terms',
        'has_login_request', 'num_exclamations', 'contains_ip_url', 'num_uppercase_words'
    ]
    feature_series = pd.Series(features.values[0], index=feature_names)
    top_features = feature_series.tail(8).sort_values(ascending=False).head(5)
    explanation_html = "<h4>Top Rule-Based Features Contributing to Prediction:</h4><ul>"
    for feat, val in top_features.items():
        explanation_html += f"<li><b>{feat}</b>: {val}</li>"
    explanation_html += "</ul>"
    return explanation_html

# Main prediction function
def predict_email(text):
    if len(text) > 5000:
        return "<p style='color:red;'>Error: Input too large. Maximum 5000 characters allowed.</p>"
    
    truncated = text[:200].replace('\n', ' ')
    logging.info(f"Received email content: {truncated!r}...")

    try:
        features = extract_features(text)
        pred = model.predict(features)[0]
        proba = model.predict_proba(features)[0][pred]

        label = "Phishing" if pred == 1 else "Legitimate"
        confidence = round(proba * 100, 2)

        highlighted = highlight_suspicious_terms(text)
        explanation_html = explain_features(features)

        return f"<h3>Prediction: {label} ({confidence}%)</h3><p>{highlighted}</p>{explanation_html}"
    except Exception:
        logging.exception("Error during prediction")
        return "<p style='color:red;'>An internal error occurred. Please try again later.</p>"
