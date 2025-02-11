from flask import Flask, request, jsonify
import subprocess
import os
import tempfile
from werkzeug.utils import secure_filename
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.before_request
def log_request():
    print(f"Received {request.method} request at {request.path}")

@app.route('/')
def index():
    return "Flask server is running!"

@app.route('/upload', methods=['POST'])
def upload_file():
    print("Processing file upload...")  # Debugging

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    filename = secure_filename(file.filename)
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, filename)

    print(f"Saving file to: {file_path}")
    file.save(file_path)

    try:
        result1 = subprocess.run(['python3', 'det1.py', file_path], capture_output=True, text=True)
        result2 = subprocess.run(['python3', 'det2.py', file_path], capture_output=True, text=True)
        result3 = {"returncode": 0, "stdout": "YARA analysis temporarily disabled", "stderr": ""} #subprocess.run(['./yara-master/yara', 'test.yara', file_path], capture_output=True, text=True)

        if result1.returncode != 0:
            return jsonify({"error": f"det1.py failed: {result1.stderr.strip()}"}), 500
        if result2.returncode != 0:
            return jsonify({"error": f"det2.py failed: {result2.stderr.strip()}"}), 500
        if result3.returncode != 0:
            return jsonify({"error": f"YARA scan failed: {result3.stderr.strip()}"}), 500

        return jsonify({
            "result1": result1.stdout.strip(),
            "result2": result2.stdout.strip(),
            "result3": result3.stdout.strip()
        })

    except FileNotFoundError as fnf_error:
        return jsonify({"error": f"Script not found: {str(fnf_error)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
