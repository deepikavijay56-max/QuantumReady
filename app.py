"""
app.py — QuantumReady Flask Web Application v2.0

What's improved:
  ✅ Handles new model dict format AND old direct model format (no crash)
  ✅ Passes line-number findings to template
  ✅ Shows quantum-safe code examples in results
  ✅ CRITICAL risk level now shown correctly (was mapped to HIGH)
  ✅ Better error messages to user
  ✅ /api/health endpoint for status check
  ✅ Score 0-100 passed correctly to template
"""

import os
import json
import tempfile
from datetime import datetime

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

from flask import Flask, request, render_template, redirect, url_for, send_file, jsonify, flash
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
import joblib
import numpy as np

import scanner
import risk_engine

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    'zip', 'py', 'java', 'js', 'ts', 'jsx', 'tsx',
    'c', 'cpp', 'cs', 'go', 'rs', 'rb', 'php', 'swift', 'kt',
    'txt', 'xml', 'json', 'yaml', 'yml',
}

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'dev-quantumready-secret'

# ─── ML MODEL ─────────────────────────────────────────────────
ML_MODEL = None
ML_FEATURE_NAMES = None
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'quantum_model.pkl')

def load_ml_model():
    global ML_MODEL, ML_FEATURE_NAMES
    if not os.path.exists(MODEL_PATH):
        print("[INFO] quantum_model.pkl not found — run: python train_model.py")
        return
    try:
        data = joblib.load(MODEL_PATH)
        if isinstance(data, dict):
            # New v2.0 format
            ML_MODEL = data['model']
            ML_FEATURE_NAMES = data.get('feature_names')
            print(f"[OK] ML Model v{data.get('version','?')} loaded ({data.get('n_features','?')} features)")
        else:
            # Old format — direct model object
            ML_MODEL = data
            ML_FEATURE_NAMES = ['RSA', 'ECC', 'SHA1', 'AES', 'PQC']
            print("[OK] ML Model (legacy 5-feature format) loaded")
    except Exception as e:
        print(f"[WARNING] Could not load ML model: {e}")

load_ml_model()


def predict_quantum_risk(features: list) -> dict:
    """Predict quantum risk using loaded ML model."""
    if ML_MODEL is None:
        return {'level': 'Unknown', 'probability': None, 'available': False}
    try:
        expected = ML_MODEL.n_features_in_
        # Pad or truncate features to match model expectation
        if len(features) < expected:
            features = features + [0] * (expected - len(features))
        elif len(features) > expected:
            features = features[:expected]

        pred = ML_MODEL.predict([features])[0]
        probs = ML_MODEL.predict_proba([features])[0]
        label_map = {0: 'Low Risk', 1: 'Medium Risk', 2: 'High Risk'}
        return {
            'level': label_map.get(int(pred), 'Unknown'),
            'score': int(pred),
            'probability': float(max(probs)),
            'available': True,
            'all_probabilities': {
                'Low Risk':    float(probs[0]),
                'Medium Risk': float(probs[1]),
                'High Risk':   float(probs[2]),
            }
        }
    except Exception as e:
        print(f"[ML prediction error] {e}")
        return {'level': 'Error', 'probability': None, 'available': False}


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def normalize_analysis(analysis: dict) -> dict:
    """Normalize analysis output for template and PDF rendering."""
    overall = str(analysis.get('overall_risk', 'LOW')).upper()
    overall_score = analysis.get('overall_score', 100)

    # Map risk label
    risk_map = {
        'CRITICAL': ('CRITICAL', overall_score),
        'HIGH':     ('HIGH',     overall_score),
        'MEDIUM':   ('MEDIUM',   overall_score),
        'LOW':      ('LOW',      overall_score),
    }
    risk_level, risk_score = risk_map.get(overall, ('LOW', 90))

    files = analysis.get('files', [])
    summary = analysis.get('summary', {})

    # Build vulnerability list (exclude safe ones)
    safe_types = {'AES', 'PQC'}
    vulnerabilities = [
        {'type': k, 'count': int(v)}
        for k, v in summary.items()
        if int(v) > 0 and k not in safe_types
    ]

    # Collect unique recommendations with code examples
    recommendations = []
    seen = set()
    for f in files:
        for rec in (f.get('analysis') or {}).get('recommendations', []):
            vuln = rec.get('vulnerability')
            if vuln and vuln not in seen:
                seen.add(vuln)
                recommendations.append(rec)

    normalized = dict(analysis)
    normalized['risk_level'] = risk_level
    normalized['risk_score'] = risk_score
    normalized['vulnerabilities'] = vulnerabilities
    normalized['recommendations'] = recommendations
    return normalized


def generate_pdf_report(report: dict, filename: str) -> str:
    """Generate a professional PDF security report."""
    try:
        pdf_filename = f"quantumready_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = os.path.join(tempfile.gettempdir(), pdf_filename)

        doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                                rightMargin=0.75*inch, leftMargin=0.75*inch,
                                topMargin=0.75*inch, bottomMargin=0.75*inch)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('T', parent=styles['Heading1'],
                                     fontSize=22, textColor=colors.HexColor('#00E5FF'),
                                     spaceAfter=10, fontName='Helvetica-Bold')
        h2 = ParagraphStyle('H2', parent=styles['Heading2'],
                             fontSize=13, textColor=colors.HexColor('#1E293B'),
                             spaceAfter=8, spaceBefore=14, fontName='Helvetica-Bold')
        code_style = ParagraphStyle('Code', parent=styles['Normal'],
                                    fontName='Courier', fontSize=9,
                                    backColor=colors.HexColor('#F1F5F9'),
                                    borderPadding=5, spaceAfter=4)

        story.append(Paragraph("QuantumReady Security Report", title_style))
        story.append(Paragraph("Post-Quantum Cryptography Assessment", styles['Normal']))
        story.append(Spacer(1, 0.15*inch))

        meta = report.get('meta', {})
        story.append(Paragraph(f"<b>File:</b> {meta.get('original_filename','Unknown')}", styles['Normal']))
        story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 0.15*inch))

        analysis = report.get('report', {})
        rl = analysis.get('risk_level', 'UNKNOWN')
        rs = analysis.get('risk_score', 0)
        color_map = {'CRITICAL': '#DC3545', 'HIGH': '#FF9800', 'MEDIUM': '#FFC107', 'LOW': '#28A745'}
        rc = color_map.get(rl, '#666')

        story.append(Paragraph("Security Assessment", h2))
        story.append(Paragraph(f"<b>Risk Level:</b> <font color='{rc}'><b>{rl}</b></font>", styles['Normal']))
        story.append(Paragraph(f"<b>QuantumReady Score:</b> {rs}/100", styles['Normal']))

        ml = report.get('ml_prediction', {})
        if ml.get('available'):
            ml_l = ml.get('level', 'Unknown')
            ml_c = '#28A745' if 'Low' in ml_l else '#FF9800' if 'Medium' in ml_l else '#DC3545'
            conf = ml.get('probability', 0)
            story.append(Paragraph(
                f"<b>ML Quantum Risk:</b> <font color='{ml_c}'><b>{ml_l}</b></font> ({conf*100:.1f}% confidence)",
                styles['Normal']))

        story.append(Spacer(1, 0.15*inch))

        vulns = analysis.get('vulnerabilities', [])
        if vulns:
            story.append(Paragraph("Detected Vulnerabilities", h2))
            broken_by = {
                'RSA': "Shor's Algorithm", 'ECC': "Shor's Algorithm",
                'MD5': "Classical Collision", 'SHA1': "Classical Collision (SHAttered)",
                'DiffieHellman': "Shor's Algorithm", 'WeakTLS': "Multiple CVEs",
                'WeakRSAKeySize': "Shor's Algorithm", 'KeyPairGenerator': "Review Needed",
            }
            risk_for = {
                'RSA': 'CRITICAL', 'ECC': 'CRITICAL', 'DiffieHellman': 'CRITICAL',
                'WeakRSAKeySize': 'CRITICAL', 'MD5': 'HIGH', 'SHA1': 'HIGH',
                'WeakTLS': 'HIGH', 'KeyPairGenerator': 'MEDIUM',
            }
            tdata = [['Vulnerability', 'Count', 'Risk', 'Broken By']]
            for v in vulns:
                vt = v['type']
                tdata.append([vt, str(v['count']), risk_for.get(vt,'MEDIUM'), broken_by.get(vt,'N/A')])
            t = Table(tdata, colWidths=[2*inch, 0.7*inch, 1.1*inch, 2.7*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), colors.HexColor('#1E293B')),
                ('TEXTCOLOR',  (0,0),(-1,0), colors.white),
                ('FONTNAME',   (0,0),(-1,0), 'Helvetica-Bold'),
                ('ALIGN',      (0,0),(-1,-1), 'CENTER'),
                ('GRID',       (0,0),(-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('ROWBACKGROUNDS', (0,1),(-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.15*inch))

        recs = analysis.get('recommendations', [])
        if recs:
            story.append(Paragraph("Quantum-Safe Fixes", h2))
            for i, rec in enumerate(recs, 1):
                story.append(Paragraph(
                    f"<b>{i}. {rec.get('vulnerability','')} — {rec.get('recommendation','')}</b>",
                    styles['Normal']))
                story.append(Paragraph(f"Standard: {rec.get('nist_standard','')}", styles['Normal']))
                story.append(Paragraph(f"Timeline: {rec.get('timeline','')}", styles['Normal']))
                if rec.get('code_before'):
                    story.append(Paragraph("<b>Replace:</b>", styles['Normal']))
                    story.append(Paragraph(rec['code_before'].replace('\n','<br/>'), code_style))
                if rec.get('code_after'):
                    story.append(Paragraph("<b>With:</b>", styles['Normal']))
                    story.append(Paragraph(rec['code_after'].replace('\n','<br/>'), code_style))
                story.append(Spacer(1, 0.12*inch))

        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("Generated by QuantumReady v2.0 — ProtoSpark 2026", styles['Italic']))
        story.append(Paragraph("Based on NIST FIPS 203/204/205 Post-Quantum Standards", styles['Italic']))

        doc.build(story)
        return pdf_path
    except Exception as e:
        print(f"[PDF error] {e}")
        return None


# ─── ROUTES ───────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('index'))
    file = request.files['file']
    if not file or file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    if not allowed_file(file.filename):
        flash('Unsupported file type. Please upload a .zip or source code file.')
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(saved_path)
    ext = filename.rsplit('.', 1)[1].lower()

    try:
        if ext == 'zip':
            findings = scanner.scan_zip(saved_path)
        else:
            result = scanner.scan_file(saved_path)
            findings = {
                'files': [{
                    'path': filename,
                    'matches': result['matches'],
                    'findings': result['findings'],
                    'score': result['score'],
                    'label': result['label'],
                }],
                'summary': {k: (1 if k in result['matches'] else 0)
                            for k in scanner.VULNERABILITY_PATTERNS.keys()},
                'overall_score': result['score'],
                'overall_label': result['label'],
                'total_findings': len(result['findings']),
            }
    except Exception as e:
        flash(f'Scan failed: {str(e)}')
        return redirect(url_for('index'))

    analysis  = normalize_analysis(risk_engine.analyze_findings(findings))
    features  = scanner.extract_features(findings['summary'])
    ml_pred   = predict_quantum_risk(features)

    report = {
        'report': analysis,
        'meta': {'original_filename': filename},
        'ml_prediction': ml_pred,
    }

    # Save JSON report
    tmp = tempfile.NamedTemporaryFile(prefix='qr_', suffix='.json', delete=False)
    tmp.write(json.dumps(report, indent=2).encode('utf-8'))
    tmp.close()

    # Generate PDF
    pdf_path = generate_pdf_report(report, filename)
    pdf_filename = os.path.basename(pdf_path) if pdf_path else None

    # Clean up single-file upload
    try:
        if ext != 'zip':
            os.remove(saved_path)
    except Exception:
        pass

    return render_template('index.html', report=report,
                           report_path=os.path.basename(tmp.name),
                           pdf_path=pdf_filename)


@app.route('/download/<path:fname>')
def download(fname):
    full = os.path.join(tempfile.gettempdir(), fname)
    if os.path.exists(full):
        return send_file(full, as_attachment=True, download_name=fname)
    return ('File not found', 404)


@app.route('/download-pdf/<path:fname>')
def download_pdf(fname):
    full = os.path.join(tempfile.gettempdir(), fname)
    if os.path.exists(full) and fname.endswith('.pdf'):
        return send_file(full, as_attachment=True, download_name=fname, mimetype='application/pdf')
    return ('PDF not found', 404)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """JSON API endpoint for programmatic scanning."""
    if 'file' not in request.files:
        return jsonify({'error': 'no file part'}), 400
    file = request.files['file']
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'invalid file'}), 400

    filename = secure_filename(file.filename)
    saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(saved_path)

    findings = scanner.scan_zip(saved_path)
    analysis = normalize_analysis(risk_engine.analyze_findings(findings))
    features = scanner.extract_features(findings['summary'])
    ml_pred  = predict_quantum_risk(features)

    return jsonify({
        'report': analysis,
        'meta': {'original_filename': filename},
        'ml_prediction': ml_pred,
    })


@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'ml_model_loaded': ML_MODEL is not None,
        'ml_features': ML_FEATURE_NAMES,
        'version': '2.0',
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)