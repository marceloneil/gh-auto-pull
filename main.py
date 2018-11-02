import hmac
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)
app.config.from_json('settings.json')

@app.route('/github_webhook', methods=['POST'])
def github_hook():
    signature = request.headers.get('X-Hub-Signature')
    sha, signature = signature.split('=')
    secret = str.encode(app.config.get('GITHUB_SECRET'))
    if request.content_length > 100000:
        return jsonify({}), 413
    hashhex = hmac.new(secret, request.get_data(), digestmod='sha1').hexdigest()
    if hmac.compare_digest(hashhex, signature):
        proc = subprocess.Popen("./pull.sh")
        proc.wait()
        return jsonify({}), 200
    else:
        return jsonify({}), 403

if __name__ == '__main__':
    app.run()
