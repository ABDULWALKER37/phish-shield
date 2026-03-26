
# Phishing URL Detector

A production-oriented phishing URL detection suite built with Streamlit and scikit-learn.  
The app scores URLs in real time by combining a trained machine-learning model with
heuristics such as tunnelling detection, suspicious TLD checks, domain age lookups and brand
impersonation markers. Results are cached for fast repeat scans, logged for observability, and
persisted to a CSV dataset for continuous retraining.

---

## ✨ Key Features
- Real-time Streamlit UI with rich verdict messaging and risk-factor breakdown.
- Trained classifier (`phishing_model.pkl`) and scaler (`scaler.pkl`) for consistent predictions.
- Advanced heuristics: Cloudflare tunnel detection, Shannon entropy, redirect counting, SSL checks, brand mimicry.
- Whitelisting via `data/legit_domains.txt` and supplemental domains for demo-friendly hosts.
- DiskCache-powered result caching plus structured logging (`phishing_detector.log`).
- Automatic dataset growth by appending each scan to `data/final_data.csv`.
- Supporting Jupyter notebook (`phishing_detection.ipynb`) for experimentation and model training.

---

## 🧱 Project Structure
```
PhishingURLModel-main/
├── app.py                     # Streamlit application entry point
├── phishing_model.pkl         # Serialized classifier
├── scaler.pkl                 # Feature scaler used during training
├── phishing_detection.ipynb   # Notebook for EDA, feature engineering, model training
├── data/
│   ├── final_data.csv         # Appended telemetry of scanned URLs (auto-created)
│   └── legit_domains.txt      # Trusted domain list to reduce false positives
├── cache/                     # DiskCache storage (created at runtime)
├── requirements.txt           # Python dependencies
├── phishing_detector.log      # Runtime logs (created at runtime)
└── readME.md                  # Documentation (this file)
```

---

## ✅ Prerequisites
- Python 3.10 or newer.
- pip (latest recommended).
- Optional: VirusTotal API key stored in a `.env` file for extended reputation checks (currently disabled in code comments).

---

## 🚀 Quick Start
1. **Download or clone**
   ```bash
   git clone <your-repo-url>
   cd PhishingURLModel-main
   ```
2. **Create a virtual environment**
   - Windows:
     ```bash
     python -m venv venv
     ```
   - macOS/Linux:
     ```bash
     python3 -m venv venv
     ```
3. **Activate the environment**
   - Windows (PowerShell):
     ```bash
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
4. **Upgrade pip (recommended)**
   ```bash
   pip install --upgrade pip
   ```
5. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
6. *(Optional)* Create a `.env` file in the project root and add:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```
   > VirusTotal integration is currently commented out in `app.py`; remove the comments to enable.

---

## ▶️ Run the Streamlit App
With the virtual environment active:
```bash
streamlit run app.py
```
Streamlit will launch the web UI and display a local URL (e.g. http://localhost:8501).  
Paste a URL into the input box and click **"🔍 Analyze URL"** to view:
- Verdict (`Legitimate`, `Phishing`, or `Unknown`)
- Confidence score and key metrics
- Risk factors (e.g. high-risk TLDs, redirects, special characters)
- Session statistics showing how many URLs have been scanned

To stop the server, return to the terminal and press `Ctrl+C`.

---

## 🧪 Working with the Notebook
`phishing_detection.ipynb` contains exploratory data analysis, feature engineering and model training
steps that produced `phishing_model.pkl` and `scaler.pkl`. Open it in Jupyter to re-train or experiment:
```bash
jupyter notebook phishing_detection.ipynb
```

---

## 🔍 Troubleshooting Tips
- **Missing model/scaler**: ensure `phishing_model.pkl` and `scaler.pkl` are present in the project root.
- **WHOIS rate limits**: repeated scans may hit external WHOIS rate limits; retry after a pause.
- **SSL/redirect errors**: some URLs deny HEAD requests; the app handles exceptions and continues.
- **Cache issues**: delete the `cache/` directory if you want a clean slate before re-running.

---

## 📄 License
Add your preferred license information here (e.g. MIT, Apache 2.0). If left blank, clarify the usage terms
in this section.

---

