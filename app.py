from flask import Flask, request, jsonify
import os
import tempfile
from werkzeug.utils import secure_filename
from flask_cors import CORS
import det1  # Importing det1.py directly

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
        # Call det1.py function directly instead of subprocess
        rule_to_strings = det1.run_yara_on_sample("test.yara", file_path)

        # Handle YARA errors
        if isinstance(rule_to_strings, dict) and "error" in rule_to_strings:
            return jsonify(rule_to_strings), 500

        malicious = bool(rule_to_strings)  # True if YARA detected something
        result1 = {
            "Malicious": "Yes" if malicious else "No",
            "Matched Strings": {rule: list(strings) for rule, strings in rule_to_strings.items()}
        }

        # Placeholder results for other scanners
        result2 = "YARA2 analysis temporarily disabled"
        result3 = "YARA3 analysis temporarily disabled"

        return jsonify({
            "result1": result1,
            "result2": result2,
            "result3": result3
        })

    except FileNotFoundError as fnf_error:
        return jsonify({"error": f"Script not found: {str(fnf_error)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
