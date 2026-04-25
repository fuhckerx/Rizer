#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FreeFire Banner Generator – using external proto files.
Synchronous, lazy token initialisation, ready for Vercel.
"""

import os
import io
import json
import time
import base64
import requests
from collections import defaultdict
from threading import Lock

from flask import Flask, request, Response, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from PIL import Image, ImageDraw, ImageFont
from Crypto.Cipher import AES

# ----- Import protobuf classes from the proto folder -----
from proto.FreeFire_pb2 import LoginReq, LoginRes
from proto.main_pb2 import GetPlayerPersonalShow
from proto.AccountPersonalShow_pb2 import AccountPersonalShowInfo

# ========================= Configuration =========================
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB53"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# Banner appearance
AVATAR_ZOOM = 1.26
AVATAR_SHIFT_X = AVATAR_SHIFT_Y = 0
BANNER_START_X, BANNER_START_Y, BANNER_END_X, BANNER_END_Y = 0.25, 0.29, 0.81, 0.65

# CDN for item images (avatar, banner, pin)
IMAGE_CDN = base64.b64decode("aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL1NoYWhHQ3JlYXRvci9pY29uQG1haW4vUE5H").decode("utf-8")

# Font files (optional – place beside app.py or remove load attempts)
FONT_FILE = "arial_unicode_bold.otf"
FONT_CHEROKEE = "NotoSansCherokee.ttf"

# ========================= Flask App =========================
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
uid_region_cache = {}
cached_tokens = defaultdict(dict)
token_lock = Lock()

# ========================= Helper Functions =========================
def pad(text: bytes) -> bytes:
    pad_len = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([pad_len] * pad_len)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))

def json_to_proto(json_data: str, proto_message):
    from google.protobuf import json_format
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def decode_protobuf(encoded_data: bytes, message_class):
    msg = message_class()
    msg.ParseFromString(encoded_data)
    return msg

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=4363983977&password=ISHITA_0AFN5_BY_SPIDEERIO_GAMING_UY12H"
    if r in {"BR", "US", "SAC", "NA"}:
        return "uid=4682784982&password=GHOST_TNVW1_RIZER_QTFT0"
    return "uid=4436915155&password=RIZER_LU4CK_RIZER_MVAIV"

def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Content-Type': "application/x-www-form-urlencoded"}
    resp = requests.post(url, data=payload, headers=headers, timeout=8)
    if resp.status_code == 200:
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")
    return "0", "0"

def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = json_to_proto(body, LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Content-Type': "application/octet-stream",
               'X-Unity-Version': "2018.4.11f1", 'ReleaseVersion': RELEASEVERSION}
    resp = requests.post(url, data=payload, headers=headers, timeout=8)
    msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, LoginRes)))
    with token_lock:
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'server_url': msg.get('serverUrl', ''),
            'expires_at': time.time() + 25200
        }

def get_token_info(region: str):
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['server_url']
    create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['server_url']

def get_account_information(uid: str, region: str):
    payload = json_to_proto(json.dumps({'a': uid, 'b': '7'}), GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, server = get_token_info(region)
    headers = {'User-Agent': USERAGENT, 'Content-Type': "application/octet-stream",
               'Authorization': token, 'ReleaseVersion': RELEASEVERSION}
    resp = requests.post(server + "/GetPlayerPersonalShow", data=data_enc, headers=headers, timeout=10)
    return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShowInfo)))

# ========================= Banner Generation =========================
def load_unicode_font(size, font_file=FONT_FILE):
    try:
        font_path = os.path.join(os.path.dirname(__file__), font_file)
        if os.path.exists(font_path):
            return ImageFont.truetype(font_path, size)
    except:
        pass
    return ImageFont.load_default()

def fetch_image_bytes(item_id):
    if not item_id or str(item_id) == "0":
        return None
    try:
        url = f"{IMAGE_CDN}/{item_id}.png"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.content
    except:
        pass
    return None

def bytes_to_image(img_bytes):
    if img_bytes:
        return Image.open(io.BytesIO(img_bytes)).convert("RGBA")
    return Image.new("RGBA", (100, 100), (0, 0, 0, 0))

def process_banner_image(data, avatar_bytes, banner_bytes, pin_bytes):
    avatar_img = bytes_to_image(avatar_bytes)
    banner_img = bytes_to_image(banner_bytes)
    pin_img = bytes_to_image(pin_bytes)

    level = str(data.get("AccountLevel") or "0")
    name = str(data.get("AccountName") or "Unknown")
    guild = str(data.get("GuildName") or "")

    TARGET_HEIGHT = 400
    zoom_size = int(TARGET_HEIGHT * AVATAR_ZOOM)
    avatar_img = avatar_img.resize((zoom_size, zoom_size), Image.LANCZOS)

    c = zoom_size // 2
    h = TARGET_HEIGHT // 2
    avatar_img = avatar_img.crop((
        c - h - AVATAR_SHIFT_X,
        c - h - AVATAR_SHIFT_Y,
        c + h - AVATAR_SHIFT_X,
        c + h - AVATAR_SHIFT_Y
    ))

    banner_img = banner_img.rotate(3, expand=True)
    bw, bh = banner_img.size
    banner_img = banner_img.crop((
        bw * BANNER_START_X,
        bh * BANNER_START_Y,
        bw * BANNER_END_X,
        bh * BANNER_END_Y
    ))

    bw, bh = banner_img.size
    banner_img = banner_img.resize(
        (int(TARGET_HEIGHT * (bw / bh) * 2), TARGET_HEIGHT),
        Image.LANCZOS
    )

    final = Image.new("RGBA", (avatar_img.width + banner_img.width, TARGET_HEIGHT))
    final.paste(avatar_img, (0, 0))
    final.paste(banner_img, (avatar_img.width, 0))

    draw = ImageDraw.Draw(final)

    font_big = load_unicode_font(125)
    font_big_c = load_unicode_font(125, FONT_CHEROKEE)
    font_small = load_unicode_font(95)
    font_small_c = load_unicode_font(95, FONT_CHEROKEE)
    font_lvl = load_unicode_font(50)

    def is_cherokee(c):
        return 0x13A0 <= ord(c) <= 0x13FF or 0xAB70 <= ord(c) <= 0xABBF

    def draw_text(x, y, text, f_main, f_alt, stroke):
        cx = x
        for ch in text:
            f = f_alt if is_cherokee(ch) else f_main
            for dx in range(-stroke, stroke+1):
                for dy in range(-stroke, stroke+1):
                    draw.text((cx+dx, y+dy), ch, font=f, fill="black")
            draw.text((cx, y), ch, font=f, fill="white")
            cx += f.getlength(ch)

    draw_text(avatar_img.width + 65, 40, name, font_big, font_big_c, 4)
    draw_text(avatar_img.width + 65, 220, guild, font_small, font_small_c, 3)

    if pin_img.size != (100, 100):
        pin_img = pin_img.resize((130, 130))
        final.paste(pin_img, (0, TARGET_HEIGHT - 130), pin_img)

    lvl = f"Lvl.{level}"
    bbox = draw.textbbox((0, 0), lvl, font=font_lvl)
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]
    draw.rectangle([final.width - w - 60, TARGET_HEIGHT - h - 50, final.width, TARGET_HEIGHT], fill="black")
    draw.text((final.width - w - 30, TARGET_HEIGHT - h - 40), lvl, font=font_lvl, fill="white")

    out = io.BytesIO()
    final.save(out, "PNG")
    out.seek(0)
    return out

# ========================= Flask Routes =========================
@app.route('/')
def home():
    return jsonify({"status": "FreeFire Banner API (proto import version)", "endpoint": "/rizer?uid=UID"})

@app.route('/rizer')
def get_banner():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Missing uid"}), 400

    # Try cached region first
    region = uid_region_cache.get(uid)
    if region:
        try:
            data = get_account_information(uid, region)
            basic = data.get("basicInfo", {})
            clan = data.get("clanBasicInfo", {})
            avatar_bytes = fetch_image_bytes(basic.get("headPic"))
            banner_bytes = fetch_image_bytes(basic.get("bannerId"))
            pin_bytes = fetch_image_bytes(basic.get("pinId"))
            img_io = process_banner_image({
                "AccountLevel": basic.get("level"),
                "AccountName": basic.get("nickname"),
                "GuildName": clan.get("clanName", "")
            }, avatar_bytes, banner_bytes, pin_bytes)
            return Response(img_io.getvalue(), mimetype="image/png")
        except:
            pass

    # Scan all regions
    for reg in SUPPORTED_REGIONS:
        try:
            data = get_account_information(uid, reg)
            uid_region_cache[uid] = reg
            basic = data.get("basicInfo", {})
            clan = data.get("clanBasicInfo", {})
            avatar_bytes = fetch_image_bytes(basic.get("headPic"))
            banner_bytes = fetch_image_bytes(basic.get("bannerId"))
            pin_bytes = fetch_image_bytes(basic.get("pinId"))
            img_io = process_banner_image({
                "AccountLevel": basic.get("level"),
                "AccountName": basic.get("nickname"),
                "GuildName": clan.get("clanName", "")
            }, avatar_bytes, banner_bytes, pin_bytes)
            return Response(img_io.getvalue(), mimetype="image/png")
        except:
            continue

    return jsonify({"error": "UID not found in any region"}), 404

@app.route('/refresh-tokens', methods=['POST'])
def refresh_tokens():
    for region in SUPPORTED_REGIONS:
        try:
            create_jwt(region)
        except:
            pass
    return jsonify({"message": "Tokens refreshed (lazy mode, only for needed regions)"}), 200

# For local testing
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
