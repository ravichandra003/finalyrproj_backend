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
    
    # Save the file to a temporary location, using tempfile for cross-platform support
    temp_dir = tempfile.gettempdir()  # Get temp directory for the current platform
    file_path = os.path.join(temp_dir, file.filename)
    
    print(temp_dir)
    file.save(file_path)
    
    try:
        # Run the Python scripts or perform other processing
        result1 = subprocess.run(['python3', 'det1.py', file_path], capture_output=True, text=True)
        result2 = subprocess.run(['python3', 'det2.py', file_path], capture_output=True, text=True)
        result3 = {"returncode": 0, "stdout": "Testing message", "stderr": ""}#subprocess.run(['./yara-master/yara', 'test.yara', file_path], capture_output=True, text=True)
        
       
        
        # Check if there was any error in running the script
        if result1.returncode != 0:
            return jsonify({"error": result1.stderr}), 500
        
        if result2.returncode != 0:
            return jsonify({"error": result2.stderr}), 500
            
        if result3.returncode != 0:
            return jsonify({"error": result3.stderr}), 500    
                       
        

        # Return multiple results as JSON
        return jsonify({
            "result1": result1.stdout.strip(),  # Process and return result1
            "result2": result2.stdout.strip(),                # Process and return result2
            "result3": result3.stdout.strip()                 # Process and return result3
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
