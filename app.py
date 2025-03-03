from flask import Flask, request, jsonify
import subprocess
import os
import tempfile
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return "Flask server is running!"

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']

    # Save the file to a temporary location
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, file.filename)
    
    print(f"Temporary directory: {temp_dir}")
    file.save(file_path)

    # Ensure YARA binary has execution permissions if it exists
    yara_executable = "yara64.exe"  # Change this path if necessary
    if os.path.exists(yara_executable):
        os.chmod(yara_executable, 0o755)

    try:
        # Run the Python scripts and YARA
        result1 = subprocess.run(['python3', 'det1.py', file_path], capture_output=True, text=True)
        result2 = {"returncode": 0, "stdout": "Testing message1", "stderr": ""} #subprocess.run(['python3', 'det2.py', file_path], capture_output=True, text=True)
        result3 = {"returncode": 0, "stdout": "Testing message2", "stderr": ""} #subprocess.run(['./yara-master/yara', 'test.yara', file_path], capture_output=True, text=True)

        # Check for errors
        for i, result in enumerate([result1, result2, result3], start=1):
            if result.returncode != 0:
                return jsonify({"error": f"Script {i} failed", "stderr": result.stderr.strip()}), 500

        # Clean up: Remove the temporary file after processing
        os.remove(file_path)

        # Return multiple results as JSON
        return jsonify({
            "result1": result1.stdout.strip(),
            "result2": result2.stdout.strip(),
            "result3": result3.stdout.strip()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
