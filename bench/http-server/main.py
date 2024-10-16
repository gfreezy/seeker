import os
from flask import Flask, send_file

app = Flask(__name__)

@app.route('/download')
def download_large_file():
    # 确保文件路径正确
    file_path = "large_file.bin"
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)