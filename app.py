import asyncio
import time
import httpx
import json
import logging
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# লগিং সেটআপ (ভারসেলের জন্য)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB52"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EU"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    """Decode protobuf, return None if invalid."""
    try:
        instance = message_type()
        instance.ParseFromString(encoded_data)
        return instance
    except Exception as e:
        logger.error(f"Protobuf decode failed: {e}")
        return None

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=4231412873&password=BY_FLEXBASE-EWZVZLX5N-IND"
    elif r == "BD":
        return "uid=4231412290&password=BY_FLEXBASE-BYV04HMKT-BD"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=uid&password=password"
    else:
        return "uid=uid&password=password"

# === Token Generation ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            logger.error(f"Access token failed: {resp.status_code} - {resp.text}")
            return "0", "0"
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    if token_val == "0" or open_id == "0":
        logger.error(f"Region {region}: Failed to get access token")
        return None

    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            logger.error(f"Region {region}: JWT request failed with status {resp.status_code}, content: {resp.text[:200]}")
            return None

        # Decode protobuf response
        decoded = decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
        if decoded is None:
            logger.error(f"Region {region}: Failed to decode protobuf, raw content (first 500 bytes): {resp.content[:500]}")
            return None

        msg = json.loads(json_format.MessageToJson(decoded))
        if not msg.get('token') or not msg.get('serverUrl'):
            logger.error(f"Region {region}: Login response missing token/serverUrl: {msg}")
            return None

        cached_tokens[region] = {
            'token': f"Bearer {msg['token']}",
            'region': msg.get('lockRegion', '0'),
            'server_url': msg.get('serverUrl', '0'),
            'expires_at': time.time() + 25200
        }
        logger.info(f"Region {region}: Token generated successfully")
        return cached_tokens[region]

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Region {list(SUPPORTED_REGIONS)[i]}: Exception during init: {result}")

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens.get(region)
    if not info:
        raise RuntimeError(f"Unable to obtain token for region {region}")
    return info['token'], info['region'], info['server_url']

async def get_region_by_uid(uid: str) -> str:
    """Fetch player region using external API"""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"https://region-api-kappa.vercel.app/region?uid={uid}", timeout=10)
            if resp.status_code != 200:
                raise ValueError("Failed to fetch region")
            data = resp.json()
            return data.get("region", "").upper()
        except Exception as e:
            logger.error(f"Error fetching region for UID {uid}: {e}")
            raise

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        decoded = decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        if decoded is None:
            raise ValueError("Failed to decode player info protobuf")
        return json.loads(json_format.MessageToJson(decoded))

def format_response(data):
    # (Your existing format_response function remains unchanged)
    return {
        "AccountInfo": {
            "AccountAvatarId": data.get("basicInfo", {}).get("headPic"),
            "AccountBPBadges": data.get("basicInfo", {}).get("badgeCnt"),
            "AccountBPID": data.get("basicInfo", {}).get("badgeId"),
            "AccountBannerId": data.get("basicInfo", {}).get("bannerId"),
            "AccountCreateTime": data.get("basicInfo", {}).get("createAt"),
            "AccountEXP": data.get("basicInfo", {}).get("exp"),
            "AccountLastLogin": data.get("basicInfo", {}).get("lastLoginAt"),
            "AccountLevel": data.get("basicInfo", {}).get("level"),
            "AccountLikes": data.get("basicInfo", {}).get("liked"),
            "AccountName": data.get("basicInfo", {}).get("nickname"),
            "AccountRegion": data.get("basicInfo", {}).get("region"),
            "AccountSeasonId": data.get("basicInfo", {}).get("seasonId"),
            "AccountType": data.get("basicInfo", {}).get("accountType"),
            "BrMaxRank": data.get("basicInfo", {}).get("maxRank"),
            "BrRankPoint": data.get("basicInfo", {}).get("rankingPoints"),
            "CsMaxRank": data.get("basicInfo", {}).get("csMaxRank"),
            "CsRankPoint": data.get("basicInfo", {}).get("csRankingPoints"),
            "EquippedWeapon": data.get("basicInfo", {}).get("weaponSkinShows", []),
            "ReleaseVersion": data.get("basicInfo", {}).get("releaseVersion"),
            "ShowBrRank": data.get("basicInfo", {}).get("showBrRank"),
            "ShowCsRank": data.get("basicInfo", {}).get("showCsRank"),
            "Title": data.get("basicInfo", {}).get("title")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": data.get("profileInfo", {}).get("clothes", []),
            "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": data.get("clanBasicInfo", {}).get("capacity"),
            "GuildID": str(data.get("clanBasicInfo", {}).get("clanId")),
            "GuildLevel": data.get("clanBasicInfo", {}).get("clanLevel"),
            "GuildMember": data.get("clanBasicInfo", {}).get("memberNum"),
            "GuildName": data.get("clanBasicInfo", {}).get("clanName"),
            "GuildOwner": str(data.get("clanBasicInfo", {}).get("captainId"))
        },
        "captainBasicInfo": data.get("captainBasicInfo", {}),
        "creditScoreInfo": data.get("creditScoreInfo", {}),
        "petInfo": data.get("petInfo", {}),
        "socialinfo": data.get("socialInfo", {})
    }

# === API Routes ===
@app.route('/info')
async def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        region = await get_region_by_uid(uid)
        if not region or region not in SUPPORTED_REGIONS:
            return jsonify({"error": "Invalid region or unsupported region"}), 400

        return_data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        formatted = format_response(return_data)
        return jsonify(formatted), 200
    except Exception as e:
        logger.exception("Error in /info")
        return jsonify({"error": "Invalid UID or server error. Please try again."}), 500

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup (only for local testing) ===
async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

# For local development, run with:
#   python app.py
# For Vercel, the app object is used directly.
if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(startup())
    app.run(host='0.0.0.0', port=5080, debug=True)