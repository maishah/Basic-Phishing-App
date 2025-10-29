# Basic-Phishing-App
A web application that detects phishing emails using machine learning and ensures explainability, whilst hardening the system against attacks.

**Objective:**
- Detect phishing content using trained Random Forest model.
- Provide explainable predictions.
- Implement robust security and input sanitization.

**Tech Stack:**
- Python 3
- scikit-learn
- NLTK
- Flask (or Gradio/FastAPI web interface)
- BeautifulSoup 4

# System Architecture
```text
Input Text
   ↓
Preprocessing Pipeline
   ↓
Feature Extraction (TF-IDF + Rule-Based)
   ↓
Random Forest Classifier
   ↓
Prediction + Explainability (Highlighted terms, key features)
```
# Components
**phishing_pipeline.py:**

  This script handles:
  - Text cleaning (HTML stripping, lowercasing, lemmatization)
  - Stopword removal
  - TF-IDF vectorization
  - Rule-based feature extraction (e.g., link count, suspicious keywords)
  - Model prediction and feature contribution explanation

**server_py:**

  Web interface/server component
  - Accepts text or pasted email content.
  - Returns Phishing/Legitimate prediction.
  - Highlights suspicious terms.
  - Logs sanitized requests securely.

**Model Artifacts**

| File                    | Description                                                                    |
| ----------------------- | ------------------------------------------------------------------------------ |
| `tfidf_vectorizer.pkl`  | Saved TF-IDF vectorizer used during training                                   |
| `phishing_rf_model.pkl` | Random Forest model trained on phishing dataset *(~60 MB — stored externally)* |

  Due to GitHub size limits, the model file is hosted externally.
  Download [here](https://drive.google.com/file/d/12xOYSfQfI9oo7Kjj3GMfrhJ57eIcohST/view?usp=sharing)
  and place it in the root folder before running.

**Security Features:**

| Area                   | Implementation                                            |
| ---------------------- | --------------------------------------------------------- |
| **Input Sanitization** | HTML stripped with BeautifulSoup; max 5000 chars enforced |
| **Secure Logging**     | Logs truncated ≤ 200 chars, timestamped, non-tamperable   |
| **Error Handling**     | Silent fallback errors, no stack traces exposed           |
| **Model Protection**   | Model file never served via API or UI                     |

**AI Model Details**
- Algorithm: Random Forest Classifier
- Features: TF-IDF text vectors + rule-based numerical indicators
- Dataset: Labeled phishing vs legitimate emails
- Explainability: Displays the top 5 features contributing to the decision

# Running the Project

**Clone the Repository**
```text
git clone https://github.com/maishah/Basic-Phishing-App.git
cd phishing-detection
```

**Add Model Files**
- Place `phishing_rf_model.pkl` and `tfidf_vectorizer.pkl` in the project root.
- If missing, download the model from the external link above.

**Run the Web App**
```text
python server.py
```
- Then open your browser at http://127.0.0.1:5000/
- Paste sample email text → click Analyze.

#Example Prediction Flow

| Step | Description                                |
| ---- | ------------------------------------------ |
| 1    | User submits email content                 |
| 2    | Text is cleaned, tokenized, vectorized     |
| 3    | Rule-based features added                  |
| 4    | Model predicts *Phishing*                  |
| 5    | Top suspicious terms highlighted on screen |

# Explainability 
- Highlights key suspicious words (e.g. “urgent”, “login”, “reset”).
- Displays behavioral features such as:
    - Number of hyperlinks
    - Presence of IP-based URLs
    - Urgency keywords frequency
- Enables analysts and users to understand why a message was flagged.

# Security by Design
- No sensitive data stored.
- Sanitized and timestamped logs.
- All exceptions handled gracefully.
- User interface prevents model download or parameter leakage.

# Author
**Maishah Dlamini**
- University of Pretoria
- Project: AI Phishing Detection System
