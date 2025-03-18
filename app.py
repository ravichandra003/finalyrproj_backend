import os
from flask import Flask, request, jsonify
import tempfile
from flask_cors import CORS
import subprocess
from concurrent.futures import ThreadPoolExecutor  # For parallel execution

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
        # Function to run a subprocess and capture its output
        def run_script(script, file_path):
            return subprocess.run(script, capture_output=True, text=True)

        # Run all three processes in parallel
        with ThreadPoolExecutor() as executor:
            future1 = executor.submit(run_script, ['python3', 'det1.py', file_path])
            future2 = executor.submit(run_script, ['python3', 'det2.py', file_path])
            future3 = executor.submit(run_script, [YARA_PATH, 'test.yara', file_path])

            # Wait for all processes to complete and get their results
            result1 = future1.result()
            result2 = future2.result()
            result3 = future3.result()

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
