from flask import Flask, request, jsonify
import hmac
import hashlib
import base64
import requests
import json
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

# 환경 변수에서 민감한 정보 가져오기
CONSUMER_SECRET = os.environ.get('CONSUMER_SECRET')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')

if not CONSUMER_SECRET or not DISCORD_WEBHOOK_URL:
    raise ValueError("CONSUMER_SECRET and DISCORD_WEBHOOK_URL must be set in environment variables")

@app.route('/webhook', methods=['GET'])
def crc_check():
    crc_token = request.args.get('crc_token')
    if crc_token:
        hash = hmac.new(
            CONSUMER_SECRET.encode('utf-8'),
            crc_token.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return jsonify({'response_token': 'sha256=' + base64.b64encode(hash).decode('utf-8')})
    return jsonify({'error': 'No crc_token'}), 400

@app.route('/webhook', methods=['POST'])
def webhook():
    signature = request.headers.get('x-twitter-webhooks-signature')
    if not signature:
        return jsonify({'error': 'No signature'}), 401

    expected_signature = 'sha256=' + base64.b64encode(
        hmac.new(
            CONSUMER_SECRET.encode('utf-8'),
            request.get_data(),
            hashlib.sha256
        ).digest()
    ).decode('utf-8')

    if signature != expected_signature:
        return jsonify({'error': 'Invalid signature'}), 401

    data = request.get_json()
    if 'tweet_create_events' in data:
        for tweet in data['tweet_create_events']:
            tweet_text = tweet['text'].replace('\n', ' ').replace('"', '\"')[:1900]
            user = tweet['user']['screen_name']
            discord_payload = {"content": f"New tweet from @{user}: {tweet_text}"}
            payload_str = json.dumps(discord_payload, ensure_ascii=False)
            headers = {"Content-Type": "application/json"}

            print("Sending payload:", payload_str)
            response = requests.post(DISCORD_WEBHOOK_URL, data=payload_str.encode('utf-8'), headers=headers)
            print("Discord response:", response.status_code, response.text)

            if response.status_code != 204:
                return jsonify({'error': 'Failed to send to Discord', 'details': response.text}), 500

    return jsonify({'status': 'OK'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))