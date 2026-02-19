import os
import time
import requests
import google.generativeai as genai
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

genai.configure(api_key=GEMINI_API_KEY)
gemini_model = genai.GenerativeModel('gemini-2.0-flash')

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'exe', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # Upload file to VirusTotal
        with open(filepath, 'rb') as f:
            vt_response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                headers={'x-apikey': VIRUSTOTAL_API_KEY},
                files={'file': f}
            )

        if vt_response.status_code != 200:
            return jsonify({'error': 'VirusTotal upload failed'}), 500

        analysis_id = vt_response.json()['data']['id']

        # Poll for results (VirusTotal takes a few seconds)
        for _ in range(10):
            time.sleep(3)
            result_response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers={'x-apikey': VIRUSTOTAL_API_KEY}
            )
            result_data = result_response.json()
            status = result_data['data']['attributes']['status']
            if status == 'completed':
                break

        stats = result_data['data']['attributes']['stats']
        results = result_data['data']['attributes']['results']

        # Build a summary of detections
        detections = {engine: info for engine, info in results.items()
                      if info['category'] == 'malicious'}

        return jsonify({
            'filename': filename,
            'stats': stats,
            'detections': detections,
            'status': status
        })

    finally:
        # Clean up uploaded file
        if os.path.exists(filepath):
            os.remove(filepath)

@app.route('/explain', methods=['POST'])
def explain_results():
    data = request.json
    stats = data.get('stats', {})
    filename = data.get('filename', 'the file')
    detections = data.get('detections', {})

    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    total = malicious + suspicious + harmless + undetected

    detection_list = ', '.join(detections.keys()) if detections else 'none'

    prompt = f"""
    A file called "{filename}" was scanned by {total} antivirus engines on VirusTotal.
    Results:
    - Malicious detections: {malicious}
    - Suspicious detections: {suspicious}
    - Clean/harmless: {harmless}
    - Undetected: {undetected}
    - Engines that flagged it as malicious: {detection_list}

    Please explain these results to someone with no technical background.
    Tell them clearly: is this file safe or dangerous? What should they do?
    Keep it friendly, simple, and under 150 words.
    """

    response = gemini_model.generate_content(prompt)
    return jsonify({'explanation': response.text})

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    app.run(debug=True)
