import os
from flask import Flask, request, jsonify
import tempfile
from flask_cors import CORS
import subprocess

app = Flask(__name__)
CORS(app)

# Get the path to the yara executable from an environment variable
YARA_PATH = os.getenv('YARA_PATH', './YARA-with-Similarity_Matching/Embedded_yara-master/yara-master/yara')

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
        result3 = subprocess.run([YARA_PATH, 'test.yara', file_path], capture_output=True, text=True)

        # Check for errors in subprocess results
        results = [result1, result2, result3]
        for i, result in enumerate(results, start=1):
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
        # Clean up the temporary file in case of an error
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
