 

from flask import Flask, request, jsonify
import os
import tempfile
from flask_cors import CORS
import subprocess
import yara  # Import the yara-python library

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
    file.save(file_path)

    try:
        # Run the Python scripts
        result1 = subprocess.run(['python3', 'det1.py', file_path], capture_output=True, text=True)
        result2 = subprocess.run(['python3', 'det2.py', file_path], capture_output=True, text=True)
        result3 = {"returncode": 0, "stdout": "Testing message2", "stderr": ""}  #subprocess.run(['./yara-master/yara', 'test.yara', file_path], capture_output=True, text=True)


        # Check for errors in subprocess results
        results = [result1, result2, result3]
        for i, result in enumerate(results, start=1):
            if isinstance(result, dict):  # Handle dictionary placeholders
                if result.get("returncode", 0) != 0:
                    return jsonify({"error": f"Script {i} failed", "stderr": result.get("stderr", "").strip()}), 500
            else:  # Handle subprocess.CompletedProcess objects
                if result.returncode != 0:
                    return jsonify({"error": f"Script {i} failed", "stderr": result.stderr.strip()}), 500

        # Clean up: Remove the temporary file after processing
        os.remove(file_path)

        # Return multiple results as JSON
        return jsonify({
            "result1": result1.stdout.strip(),
            "result2": result2["stdout"].strip(),  # Access dictionary value
            "result3": result3["stdout"].strip()   # Access dictionary value
        })

    except Exception as e:
        # Clean up the temporary file in case of an error
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
