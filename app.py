from flask import Flask, render_template, request, redirect, url_for, flash
from main import CybersecurityThreatDetector
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # For flash messages

detector = CybersecurityThreatDetector()
if hasattr(detector, 'load_models'):
    detector.load_models()

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/network', methods=['GET', 'POST'])
def network():
    result = None
    if request.method == 'POST':
        try:
            # Expecting CSV text input for network data
            csv_data = request.form['network_data']
            import pandas as pd
            from io import StringIO
            df = pd.read_csv(StringIO(csv_data))
            result = detector.detect_network_threats(df)
        except Exception as e:
            flash(f"Error processing network data: {e}", 'danger')
    return render_template('network.html', result=result)

@app.route('/malware', methods=['GET', 'POST'])
def malware():
    results = None
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            results = detector.detect_malware([filepath])
            # Optionally delete the file after detection
            os.remove(filepath)
    return render_template('malware.html', results=results)

@app.route('/phishing', methods=['GET', 'POST'])
def phishing():
    results = None
    if request.method == 'POST':
        email_text = request.form.get('email_text', '')
        if email_text.strip() == '':
            flash('Please enter email text', 'danger')
        else:
            results = detector.detect_phishing([email_text])
    return render_template('phishing.html', results=results)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
