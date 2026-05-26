from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Flask is working!</h1>"

@app.route('/api/test')
def test_api():
    return jsonify({'message': 'API is working!'})

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5001)