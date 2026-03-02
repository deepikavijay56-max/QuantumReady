# QuantumReady

QuantumReady is a small academic project that performs static analysis on uploaded source code ZIP archives to detect quantum-vulnerable cryptographic algorithms and provide post-quantum recommendations.

Quick overview
- Backend: Python + Flask
- Scanner: `scanner.py` — extracts ZIPs, searches files for keywords
- Risk engine: `risk_engine.py` — rule-based risk scoring and recommendations
- App: `app.py` — web UI and API endpoint

How to run (development)

1. Create and activate a virtual environment (recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Run the app:

```powershell
python app.py
```

3. Open `http://127.0.0.1:5000` in a browser and upload a ZIP of your source files.

Project structure

- `scanner.py`: ZIP extraction and static scanning for keywords (RSA, ECC, SHA1, DiffieHellman, KeyPairGenerator).
- `risk_engine.py`: Rule-based risk classification and recommendation builder.
- `app.py`: Flask app with `/scan` web endpoint and `/api/scan` JSON API.
- `templates/index.html`: Simple dashboard UI.
Notes for assessment
- Code is commented for academic clarity.
- The scanner uses simple regex-based keyword detection (rule-based). For production, use robust parsing / AST analysis.
# QuantumReady — Post-Quantum Cryptography Migration Assistant

QuantumReady is a small academic project that performs static analysis on uploaded source code to detect quantum-vulnerable cryptographic algorithms and provide post-quantum recommendations.

## Quick Start (Development)

1. **Active Environment**:
   ```powershell
   .\.venv\Scripts\activate
   ```

2. **Train the ML Model**:
   ```powershell
   python train_model.py
   ```

3. **Run the App**:
   ```powershell
   python app.py
   ```

4. **Access the Dashboard**:
   Open `http://127.0.0.1:5000` in a browser and upload a file or ZIP.

## Project Structure

- `app.py`: Main Flask application (UI and API).
- `scanner.py`: Static analysis engine for detecting crypto keywords.
- `risk_engine.py`: Rule-based risk assessment and recommendations.
- `train_model.py`: Script to train the ML risk predictor.
- `templates/`: HTML UI templates.
- `static/`: CSS and assets.

## Vulnerability Detection

The scanner detects various algorithms broken by Shor's or Grover's algorithms:
- **RSA / ECC**: Critical risk (broken by Shor's).
- **SHA1 / MD5**: High risk (collision/weakness).
- **Legacy Ciphers**: Medium risk.

## Team
ProtoSpark 2026
