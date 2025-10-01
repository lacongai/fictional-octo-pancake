from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import threading
import logging
import time

app = Flask(__name__)

@app.route('/')
def home():
    return "make api telegram: @henntaiiz"
    
# Configure logging
app.logger.setLevel(logging.DEBUG)

# Global usage counters
usage_counter = 0
usage_lock = threading.Lock()
MAX_USAGE = 40

def load_tokens(server_name):
    try:
        # mapping server -> file
        mapping = {
            "IND": "token_ind.json",
            "BR": "token_br.json",
            "US": "token_br.json",
            "SAC": "token_br.json",
            "NA": "token_br.json",
            "VN": "token_vn.json",
            "BD": "token_bd.json",
        }

        # nếu không có trong mapping thì mặc định lấy token_bd.json
        file_name = mapping.get(server_name, "token_bd.json")

        with open(file_name, "r", encoding="utf-8") as f:
            tokens = json.load(f)

        app.logger.info(f"Loaded tokens for server {server_name} ({file_name})")
        return tokens

    except Exception as e:
        app.logger.error(
            f"Error loading tokens for server {server_name}: {str(e)}",
            exc_info=True
        )
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Encryption failed: {str(e)}", exc_info=True)
        return None

def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {str(e)}", exc_info=True)
        return None

async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=edata, headers=headers, timeout=10) as response:
                if response.status != 200:
                    app.logger.error(f"Request failed with status code: {response.status}")
                    return response.status
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {str(e)}", exc_info=True)
        return None

async def send_multiple_requests(uid, server_name, url):
    try:
        region = server_name
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            app.logger.error("Failed to create protobuf message.")
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None
        tasks = []
        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        for i in range(100):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Update usage counter
        with usage_lock:
            global usage_counter
            usage_counter += 1
            app.logger.info(f"Usage counter incremented to {usage_counter}")
            
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {str(e)}", exc_info=True)
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {str(e)}", exc_info=True)
        return None

def enc(uid):
    try:
        protobuf_data = create_protobuf(uid)
        if protobuf_data is None:
            return None
        encrypted_uid = encrypt_message(protobuf_data)
        return encrypted_uid
    except Exception as e:
        app.logger.error(f"Error in enc: {str(e)}", exc_info=True)
        return None

def make_request(encrypt, server_name, token):
    try:
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        elif server_name in {"VN"}:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
        edata = bytes.fromhex(encrypt)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        hex_data = response.content.hex()
        binary = bytes.fromhex(hex_data)
        decode = decode_protobuf(binary)
        if decode is None:
            app.logger.error("Protobuf decoding returned None.")
        return decode
    except Exception as e:
        app.logger.error(f"Error in make_request: {str(e)}", exc_info=True)
        return None

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {str(e)}", exc_info=True)
        return None

def get_region_by_uid(uid):
    """Fetch player region with retries and fallback to server checks"""
    # Try external API with retries
    for attempt in range(3):
        try:
            response = requests.get(f"https://regoin-api.vercel.app/region?uid={uid}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                region = data.get("region", "").upper()
                if region:
                    app.logger.info(f"Got region from API: {region}")
                    return region
            app.logger.warning(f"API attempt {attempt+1} failed with status {response.status_code}")
        except Exception as e:
            app.logger.warning(f"API attempt {attempt+1} failed: {str(e)}")
        time.sleep(0.5)  # Short delay between retries
    
    # Fallback to direct server checks
    app.logger.warning("External API failed, using direct server checks")
    servers = [
        ("IND", "token_ind.json"),
        ("BR", "token_br.json"),
        ("US", "token_bd.json"),
        ("SAC", "token_bd.json"),
        ("NA", "token_bd.json"),
        ("BD", "token_bd.json"),
        ("VN", "token_vn.json")
    ]
    
    for server_name, token_file in servers:
        try:
            with open(token_file, "r") as f:
                tokens = json.load(f)
                if not tokens:
                    continue
                    
            token = tokens[0]['token']
            encrypted_uid = enc(uid)
            if not encrypted_uid:
                continue
                
            if server_name == "IND":
                url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
            elif server_name == {"BR", "US", "SAC", "NA"}:
                url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
            elif server_name == "VN":
                url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
            else:
                url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

            edata = bytes.fromhex(encrypted_uid)
            headers = {
                'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                'Authorization': f"Bearer {token}",
                'Content-Type': "application/x-www-form-urlencoded",
            }
            response = requests.post(url, data=edata, headers=headers, timeout=5, verify=False)
            
            if response.status_code == 200:
                app.logger.info(f"Found valid region: {server_name}")
                return server_name
                
        except Exception as e:
            app.logger.error(f"Server check for {server_name} failed: {str(e)}")
    
    app.logger.error("All region detection methods failed")
    return None

@app.route('/like', methods=['GET'])
def handle_requests():
    try:
        uid = request.args.get("uid")
        if not uid:
            app.logger.error("UID is required")
            return jsonify({"error": "UID is required"}), 400

        # Check usage limit
        with usage_lock:
            if usage_counter >= MAX_USAGE:
                app.logger.warning(f"Usage limit reached: {usage_counter}/{MAX_USAGE}")
                return jsonify({
                    "error": "Usage limit reached (40/40)",
                    "status": "Failed",
                    "usage": f"{usage_counter}/{MAX_USAGE}"
                }), 429

        # Get region from combined method
        server_name = get_region_by_uid(uid)
        if not server_name:
            app.logger.error("Failed to detect region for UID")
            return jsonify({
                "error": "Failed to detect player region",
                "status": "Failed",
                "usage": f"{usage_counter}/{MAX_USAGE}"
            }), 400
        
        app.logger.info(f"Using server region: {server_name} for UID: {uid}")

        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return jsonify({
                "error": "Token loading failed",
                "status": "Failed",
                "usage": f"{usage_counter}/{MAX_USAGE}"
            }), 500

        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            app.logger.error("Encryption of UID failed.")
            return jsonify({
                "error": "UID encryption failed",
                "status": "Failed",
                "usage": f"{usage_counter}/{MAX_USAGE}"
            }), 500

        # Get initial like count
        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            app.logger.error("Failed to retrieve initial player info.")
            return jsonify({
                "error": "Initial player info request failed",
                "status": "Failed",
                "usage": f"{usage_counter}/{MAX_USAGE}"
            }), 500
            
        try:
            jsone = MessageToJson(before)
            data_before = json.loads(jsone)
            before_like = data_before.get('AccountInfo', {}).get('Likes', 0)
            before_like = int(before_like) if before_like else 0
        except Exception as e:
            app.logger.error(f"Error parsing initial data: {str(e)}")
            before_like = 0
            
        app.logger.info(f"Likes before command: {before_like}")

        # Determine endpoint URL
        if server_name == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        elif server_name == "VN":
            url = "https://clientbp.ggblueshark.com/LikeProfile"
        else:
            url = "https://clientbp.ggblueshark.com/LikeProfile"
            
        # Send like requests
        asyncio.run(send_multiple_requests(uid, server_name, url))

        # Get updated like count
        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            app.logger.error("Failed to retrieve player info after like requests.")
            return jsonify({
                "error": "Post-request player info failed",
                "status": "Failed",
                "usage": f"{usage_counter}/{MAX_USAGE}"
            }), 500
            
        try:
            jsone_after = MessageToJson(after)
            data_after = json.loads(jsone_after)
            after_like = int(data_after.get('AccountInfo', {}).get('Likes', 0))
            player_name = str(data_after.get('AccountInfo', {}).get('PlayerNickname', ''))
        except Exception as e:
            app.logger.error(f"Error parsing final data: {str(e)}")
            after_like = before_like
            player_name = "Unknown"
            
        like_given = after_like - before_like
        status = 1 if like_given > 0 else 0
        
        # Get current usage
        with usage_lock:
            current_usage = usage_counter
            
        result = {
            "LikesGivenByAPI": like_given,
            "LikesbeforeCommand": before_like,
            "LikesafterCommand": after_like,
            "PlayerNickname": player_name,
            "status": status,
            "usage": f"{current_usage}/{MAX_USAGE}"
        }
        app.logger.info(f"Request processed successfully for UID: {uid}")
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return jsonify({
            "error": str(e),
            "status": "Failed",
            "usage": f"{usage_counter}/{MAX_USAGE}"
        }), 500

@app.route('/reset', methods=['GET'])
def reset_usage():
    try:
        with usage_lock:
            global usage_counter
            usage_counter = 0
            app.logger.info("Usage counter reset")
        return jsonify({
            "message": "Usage counter reset successfully",
            "usage": f"0/{MAX_USAGE}"
        }), 200
    except Exception as e:
        app.logger.error(f"Error resetting usage: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def api_status():
    try:
        with usage_lock:
            status = "Active" if usage_counter < MAX_USAGE else "Limit Reached"
            usage = f"{usage_counter}/{MAX_USAGE}"
        app.logger.info(f"Status checked: {status}, Usage: {usage}")
        return jsonify({
            "status": status,
            "usage": usage
        }), 200
    except Exception as e:
        app.logger.error(f"Error checking status: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/update', methods=['GET'])
def api_update():
    try:
        with usage_lock:
            status = "Active" if usage_counter < MAX_USAGE else "Limit Reached"
            usage = f"{usage_counter}/{MAX_USAGE}"
        app.logger.info(f"Update checked: {status}, Usage: {usage}")
        return jsonify({
            "status": status,
            "usage": usage,
            "update": "yes"
        }), 200
    except Exception as e:
        app.logger.error(f"Error checking update: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False, threaded=True)
