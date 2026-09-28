from flask import Flask, request, jsonify
import requests, urllib3, base64, json, logging, time, re, datetime as dt
from datetime import datetime, timezone
from Crypto.Cipher import AES
from google.protobuf.internal.decoder import _DecodeVarint32
from urllib.parse import urlparse, parse_qs

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("ff")

app = Flask(__name__)
app.json.sort_keys = False
_cache = {}

_session = requests.Session()
_session.mount("http://",  requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=16))
_session.mount("https://", requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=16))
_session.headers.update({
    "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1", "ReleaseVersion": "OB55",
})

AES_KEY, AES_IV = b"Yg&tc%DEuh6%Zc^8", b"6oyZDr22E3ychjM%"
FF_NICKNAME_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"

OAUTH_URL       = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
INSPECT_URL     = "https://100067.connect.garena.com/oauth/token/inspect"
TARGET_API_URL  = "https://api-otrss.garena.com/support/callback/"
MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"
NICKNAME_HOST   = "clientbp.ppmainecoonghj.com"

T_OAUTH, T_MAJOR, T_INSPECT, T_NICK = (5, 12), (5, 15), (5, 10), 7

REGIONS = ["BD", "VN", "SG", "TW", "ID", "TH", "MY", "PH", "BR", "PK", "IND", "RU", "SA", "EG"]
PLATFORM = {r: i+1 for i, r in enumerate(["BD","SG","ID","VN","TH","TW","MY","PH","BR","PK","IND","RU","SA","EG"])}
LANG = {r: r.lower() for r in REGIONS}


class RateLimitError(Exception): pass
class ForbiddenError(Exception): pass
class GarenaError(Exception): pass


# ═══════════════ PROTOBUF ═══════════════
def _pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n] * n)

def encrypt(b):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(_pad(b))

def _vi(v):
    out = b""
    while True:
        x = v & 0x7F; v >>= 7
        out += bytes([x | 0x80]) if v else bytes([x])
        if not v: return out

def _enc(fields):
    out = b""
    for fn in sorted(fields):
        v = fields[fn]
        k = _vi((fn << 3) | (0 if isinstance(v, int) else 2))
        if isinstance(v, int): out += k + _vi(v)
        elif isinstance(v, str):
            d = v.encode(); out += k + _vi(len(d)) + d
        elif isinstance(v, bytes): out += k + _vi(len(v)) + v
    return out

def _pbD(data):
    i, out = 0, {}
    while i < len(data):
        try: tag, i = _DecodeVarint32(data, i)
        except Exception: break
        fn, wt = tag >> 3, tag & 7
        if wt == 0: out[fn], i = _DecodeVarint32(data, i)
        elif wt == 2:
            ln, i = _DecodeVarint32(data, i); out[fn] = data[i:i+ln]; i += ln
        elif wt == 1: out[fn] = data[i:i+8]; i += 8
        elif wt == 5: out[fn] = data[i:i+4]; i += 4
        else: break
    return out


# ═══════════════ JWT / NICKNAME ═══════════════
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")

def scan_jwts(text: str) -> list:
    return JWT_RE.findall(text or "")

def decode_jwt(token):
    try:
        p = token.split(".")[1]
        p += "=" * ((4 - len(p) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}

def decode_nickname(enc):
    try:
        raw = base64.b64decode(enc)
        return bytes(b ^ FF_NICKNAME_KEY[i % len(FF_NICKNAME_KEY)] for i, b in enumerate(raw)).decode("utf-8", "replace")
    except Exception:
        return "Unknown"

def extract_nickname(token):
    pl = decode_jwt(token)
    n = pl.get("nickname")
    return decode_nickname(n) if isinstance(n, str) else pl.get("name", "Unknown")

def ts_to_human(data):
    if isinstance(data, dict):
        return {k: (f"{v} ({datetime.fromtimestamp(v, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
                    if isinstance(v, (int, float)) and 1_000_000_000 < v < 3_000_000_000
                    else ts_to_human(v)) for k, v in data.items()}
    if isinstance(data, list):
        return [(f"{x} ({datetime.fromtimestamp(x, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')})"
                 if isinstance(x, (int, float)) and 1_000_000_000 < x < 3_000_000_000
                 else ts_to_human(x)) for x in data]
    return data


# ═══════════════ PAYLOAD ═══════════════
def build_payload(open_id, access_token, region="BD"):
    r = region.upper()
    return _enc({
        3: dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 4: "free fire",
        5: PLATFORM.get(r, 1), 7: "2.114.2",
        8: "Android OS 13 / API-33 (TP1A.220624.014/250515V1977)", 9: "Handheld",
        10: "Vietnamobile", 11: "WIFI", 12: 1612, 13: 720, 14: "320",
        15: "ARM64 FP ASIMD AES | 2301 | 8", 16: 3796, 17: "PowerVR Rogue GE8320",
        18: "OpenGL ES 3.2 build 1.13@5776728",
        19: "Google|b310289f-a93e-425c-80b1-022f1573314b", 20: "117.5.152.105",
        21: LANG.get(r, "bd"), 22: str(open_id)[:32].ljust(32, "0"),
        23: "4", 24: "Handheld", 25: "OPPO CPH2477", 26: r,
        29: str(access_token)[:64].ljust(64, "0"), 30: 1,
        41: "Vietnamobile", 42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 48610, 61: 19355, 62: 697, 64: 19450, 65: 48610, 66: 19450, 67: 48610,
        73: 1, 74: "/data/app/~~-c03C_kN-zT9GYD2V-rlYg==/com.dts.freefireth-0rkKD-122NiODJDk0HBSrA==/lib/arm64",
        76: 1, 77: "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~-c03C_kN-zT9GYD2V-rlYg==/com.dts.freefireth-0rkKD-122NiODJDk0HBSrA==/base.apk",
        78: 3, 79: 2, 81: "64", 83: "2019115657", 85: 3, 86: "OpenGLES2",
        87: 3071, 88: 4, 90: "Thái Bình", 91: "20", 92: 14886, 93: "android_max",
        94: "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY=",
        95: 110009, 96: '{"cur_rate":[60,90]}', 97: 1, 98: 1, 99: "4", 100: "4",
        102: b"JW\x010@V^\x00b\x001e", 103: 1, 104: 64816, 105: 1,
        106: "https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|211c933168f55902c7dfbfd8c4e2957d",
    })


# ═══════════════ PARSER ═══════════════
_PATTERNS = [b"Exploiting loopholes", b"_AUTH_ABNORMAL_GAME_CLIENT", b"_AUTH_INVALID_ACCOUNT",
             b"_AUTH_ACCOUNT_BANNED", b"BR_PLATFORM_INVALID_PLATFORM", b"SignError"]

def _garena_msg(raw):
    for p in _PATTERNS:
        i = raw.find(p)
        if i != -1:
            c = raw[max(0, i-3):i+len(p)+10]
            return "".join(ch if 32 <= ord(ch) < 127 else " " for ch in c.decode("utf-8", "ignore")).strip() or p.decode()
    if len(raw) < 200 and b"eyJ" not in raw:
        t = raw.decode("utf-8", "ignore").strip()
        if t and sum(1 for c in t if 32 <= ord(c) < 127) / len(t) > 0.7:
            return "".join(c if 32 <= ord(c) < 127 else " " for c in t).strip()
    return None

def parse_major(raw):
    msg = _garena_msg(raw)
    if msg and b"eyJ" not in raw:
        return {"error_message": msg}

    info_token = ""
    account_uid, region = "0", ""

    try:
        fields = _pbD(raw)
        def s(n):
            v = fields.get(n, b"")
            return v.decode("utf-8", "replace").strip() if isinstance(v, bytes) else str(v)
        def i(n):
            v = fields.get(n, 0)
            return int(v) if isinstance(v, int) else 0

        account_uid = str(i(1))
        region      = s(2)

        v = fields.get(8)
        if isinstance(v, bytes):
            jwts = scan_jwts(v.decode("utf-8", "ignore"))
            if jwts: info_token = jwts[0]

        if not info_token:
            for fn, v in fields.items():
                if not isinstance(v, bytes): continue
                jwts = scan_jwts(v.decode("utf-8", "ignore"))
                if jwts: info_token = jwts[0]; break
    except Exception as e:
        logger.warning("parse_major error: %s", e)

    if not info_token:
        jwts = scan_jwts(raw.decode("utf-8", "ignore"))
        if jwts: info_token = jwts[0]

    if not info_token: return None

    return {"token": info_token, "account_uid": account_uid, "region": region}


# ═══════════════ API CALLS ═══════════════
def get_oauth(uid, password):
    r = _session.post(OAUTH_URL, json={
        "client_id": 100067,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2, "password": password, "response_type": "token", "uid": uid,
    }, timeout=T_OAUTH, verify=False)
    try: data = r.json()
    except Exception: data = {"raw": r.text}
    if r.status_code == 429 or "captcha" in json.dumps(data, default=str).lower():
        raise RateLimitError("Rate-limit / captcha")
    if r.status_code != 200:
        err = (data.get("error") or {}).get("message") if isinstance(data.get("error"), dict) else None
        raise ValueError(f"OAuth {r.status_code}: {err or data}")
    inner = data.get("data") or {}
    if not (inner.get("access_token") and inner.get("open_id")):
        raise ValueError("OAuth thiếu access_token/open_id")
    return inner["access_token"], inner["open_id"], data

def get_nickname(open_id, access_token=""):
    try:
        r = _session.post(f"https://{NICKNAME_HOST}/GenerateNickname",
                          headers={"Host": NICKNAME_HOST, "Authorization": "Bearer",
                                   "ReleaseVersion": "OB55", "X-GA": "v1 1",
                                   "X-GA-SV": str(int(time.time())),
                                   "X-Unity-Version": "2018.4.12f1",
                                   "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"},
                          data=encrypt(_enc({1: "en", 2: open_id})), timeout=T_NICK, verify=False)
        return r.text.strip() if r.status_code == 200 else ""
    except Exception: return ""

def get_major(open_id, access_token, region="BD"):
    r = _session.post(MAJOR_LOGIN_URL, data=encrypt(build_payload(open_id, access_token, region)),
                      headers={"X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
                               "ReleaseVersion": "OB55",
                               "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"},
                      verify=False, timeout=T_MAJOR)
    if r.status_code == 403: raise ForbiddenError("MajorLogin 403")
    if r.status_code != 200:
        raise ValueError(f"MajorLogin {r.status_code}: {r.content[:150].decode('utf-8', 'ignore')}")
    res = parse_major(r.content)
    if res and "error_message" in res: raise GarenaError(res["error_message"])
    if not res: raise ValueError("Không parse được token")

    jwt = decode_jwt(res["token"])
    account_region = (res.get("region") or jwt.get("country_code") or region).upper()
    if account_region != region.upper():
        raise GarenaError(f"BR_PLATFORM_INVALID_PLATFORM req={region} acc={account_region}")

    res["region"]     = account_region
    res["account_id"] = str(jwt.get("account_id", res["account_uid"]))
    res["nickname"]   = get_nickname(open_id, access_token) or extract_nickname(res["token"])
    return res

def get_major_auto(open_id, access_token):
    tried = {}
    for region in REGIONS:
        try:
            r = get_major(open_id, access_token, region)
            r["region_used"] = region
            return r
        except GarenaError as e:
            tried[region] = str(e)
            if "BR_PLATFORM_INVALID_PLATFORM" in str(e): continue
            raise
        except (ForbiddenError, ValueError) as e:
            tried[region] = str(e); continue
    raise GarenaError(f"Không region nào hợp lệ: {tried}")


# ═══════════════ CORE LOGIN ═══════════════
def _do_login(uid, password, retries=3):
    last = "Unknown"
    for attempt in range(1, retries + 1):
        try:
            access_token, open_id, auth = get_oauth(int(uid), password)
        except RateLimitError as e:
            last = str(e)
            if attempt < retries: time.sleep(1.5 * attempt); continue
            return {"status": "error", "step": "oauth", "message": last, "creator": "@henntaii"}, 429
        except (requests.Timeout, requests.ConnectionError) as e:
            last = f"Network: {type(e).__name__}"
            if attempt < retries: time.sleep(0.4 * attempt); continue
            return {"status": "error", "step": "oauth", "message": last, "creator": "@henntaii"}, 504
        except Exception as e:
            return {"status": "error", "step": "oauth", "message": str(e), "creator": "@henntaii"}, 502

        try:
            major = get_major_auto(open_id, access_token)
        except GarenaError as e:
            return {"status": "error", "step": "major_login", "message": str(e),
                    "hint": "Garena từ chối request.", "creator": "@henntaii"}, 400
        except ForbiddenError as e:
            return {"status": "error", "step": "major_login", "message": str(e), "creator": "@henntaii"}, 403
        except Exception as e:
            last = str(e)
            if attempt < retries: time.sleep(0.4 * attempt); continue
            return {"status": "error", "step": "major_login", "message": last, "creator": "@henntaii"}, 502

        oauth_inner = auth.get("data") or {}

        # ═══ RESPONSE GỌN — 1 TOKEN CHÍNH + 2 TOKEN PHỤ ═══
        return {
            "status": "success",
            "message": "Login successful",
            "data": {
                "uid":  uid,
                "pass": password,
                "guest_auth": ts_to_human(auth),

                # ⚡ TOKEN CHÍNH — dùng để login game / extract (KHÔNG dùng JWT)
                "token":         access_token,

                # Token phụ (nếu cần)
                "refresh_token": oauth_inner.get("refresh_token", ""),
                "jwt_token":     major["token"],

                # Thông tin account
                "open_id":     str(open_id),
                "account_id":  major["account_id"],
                "nickname":    major["nickname"],
                "region":      "N/A",
            },
            "creator": "@henntaii",
            "retry_attempts": attempt - 1,
            "cached": False,
        }, 200

    return {"status": "error", "message": f"Thất bại: {last}", "creator": "@henntaii"}, 502


# ═══════════════ ROUTES ═══════════════
@app.after_request
def no_cache(r):
    r.headers["Cache-Control"] = "no-store"
    return r

@app.route("/guest", methods=["GET"])
@app.route("/token", methods=["GET"])
@app.route("/jwt", methods=["GET"])
@app.route("/Bmw", methods=["GET"])
def guest_login():
    uid = (request.args.get("uid") or request.args.get("u") or "").strip()
    password = (request.args.get("password") or request.args.get("pass") or request.args.get("p") or "").strip()
    force = request.args.get("refresh") == "1"
    try: retries = max(1, min(int(request.args.get("retry", 3)), 10))
    except ValueError: retries = 3

    if not uid or not uid.isdigit() or not password:
        return jsonify({"status": "error", "message": "UID phải là số và password bắt buộc",
                        "creator": "@henntaii"}), 400

    key = f"{uid}:{password}"
    if not force and key in _cache:
        r = dict(_cache[key]); r["cached"] = True
        return jsonify(r), 200

    result, code = _do_login(uid, password, retries)
    if result.get("status") == "success": _cache[key] = result
    return jsonify(result), code

@app.route("/cache/clear", methods=["GET"])
def clear_cache():
    uid = request.args.get("uid", ""); pw = request.args.get("password", "")
    if uid and pw:
        removed = _cache.pop(f"{uid}:{pw}", None)
        return jsonify({"status": "ok", "removed": bool(removed), "total": len(_cache)})
    n = len(_cache); _cache.clear()
    return jsonify({"status": "ok", "cleared": n})

@app.route("/debug", methods=["GET"])
def debug_login():
    uid = (request.args.get("uid") or "").strip()
    password = (request.args.get("password") or "").strip()
    if not uid.isdigit() or not password:
        return jsonify({"error": "uid (số) và password bắt buộc"}), 400
    out = {"uid": uid, "steps": {}}
    try:
        access_token, open_id, auth = get_oauth(int(uid), password)
        out["steps"]["oauth"] = {"status": "ok", "open_id": open_id}
    except Exception as e:
        return jsonify({"steps": {"oauth": {"error": str(e)}}}), 502
    for region in REGIONS:
        try:
            r = _session.post(MAJOR_LOGIN_URL, data=encrypt(build_payload(open_id, access_token, region)),
                              headers={"X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
                                       "ReleaseVersion": "OB55"},
                              verify=False, timeout=T_MAJOR)
            e = {"http": r.status_code, "len": len(r.content)}
            msg = _garena_msg(r.content)
            if msg and b"eyJ" not in r.content: e["error"] = msg
            p = parse_major(r.content)
            if p and "token" in p:
                e.update(OK=True, server_region=p.get("region"))
                out["steps"][region] = e; out["winner"] = region; break
            out["steps"][region] = e
        except Exception as ex:
            out["steps"][region] = {"error": str(ex)}
        time.sleep(0.3)
    return jsonify(out)

@app.route("/test_region", methods=["GET"])
def test_region():
    uid = (request.args.get("uid") or "").strip(); pw = (request.args.get("password") or "").strip()
    if not uid.isdigit() or not pw:
        return jsonify({"error": "uid (số) và password bắt buộc"}), 400
    try:
        access_token, open_id, _ = get_oauth(int(uid), pw)
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    out = {"uid": uid, "results": {}}
    winner = None
    for region in REGIONS:
        try:
            r = _session.post(MAJOR_LOGIN_URL, data=encrypt(build_payload(open_id, access_token, region)),
                              headers={"X-GA": "v1 1", "X-GA-SV": str(int(time.time())),
                                       "ReleaseVersion": "OB55"},
                              verify=False, timeout=5)
            body = r.content
            if len(body) < 200:
                out["results"][region] = {"http": r.status_code, "error": body[:80].decode("utf-8", "ignore")}
                continue
            p = parse_major(body)
            if p and "token" in p:
                out["results"][region] = {"http": r.status_code, "OK": True, "server_region": p.get("region")}
                winner = region; break
            out["results"][region] = {"http": r.status_code, "no_jwt": True, "len": len(body)}
        except Exception as e:
            out["results"][region] = {"error": str(e)}
        time.sleep(0.4)
    return jsonify({"success": bool(winner), "region_match": winner, "data": out})

@app.route("/access", methods=["GET"])
@app.route("/a", methods=["GET"])
@app.route('/rizer', methods=['GET'])
def access_endpoint():
    t0 = time.time()
    access_token = request.args.get("access_token") or request.args.get("a") or request.args.get("access")
    if not access_token: return jsonify({"error": "Missing access_token"}), 400
    try:
        r = _session.get(f"{INSPECT_URL}?token={access_token}", timeout=T_INSPECT).json()
        open_id = r.get("open_id")
        if not open_id: return jsonify({"error": "open_id not found"}), 400
    except Exception as e:
        return jsonify({"error": f"Inspect failed: {e}"}), 500
    try:
        major = get_major_auto(open_id, access_token)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 401
    return jsonify({
        "success": True,
        "token": access_token,          # access_token dùng để login game
        "jwt_token": major["token"],
        "open_id": str(open_id),
        "account_id": major["account_id"],
        "nickname": major["nickname"],
        "region": "N/A",
        "response_time_ms": round((time.time() - t0) * 1000, 2),
    })

@app.route('/eat', methods=['GET'])
@app.route('/e', methods=['GET'])
def rizer():
    eat = request.args.get('eat_token') or request.args.get("e")
    if not eat: return jsonify({"status": "error", "message": "Missing eat_token"}), 400
    fwd = {h: v for h, v in request.headers.items()
           if h.lower() not in ['host', 'content-length', 'connection', 'transfer-encoding']}
    try:
        s = requests.Session()
        r = s.get(TARGET_API_URL, params={'access_token': eat}, headers=fwd, allow_redirects=False)
        while r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get('Location')
            if not loc: break
            if not loc.startswith(('http://', 'https://')):
                loc = urlparse(TARGET_API_URL)._replace(path=loc).geturl()
            r = s.get(loc, headers=fwd, allow_redirects=False)
        at = parse_qs(urlparse(r.url).query).get('access_token', [None])[0]
        if not at: return jsonify({"status": "error", "message": "access_token not found"}), 500
        return jsonify({"status": "success",
                        "data": {"owner": "HenTaiz", "telegram": "@henntaiiz",
                                 "thanks": "THANKS FOR USING!", "access_token": at}}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error: {e}"}), 500

@app.route('/decode', methods=['GET'])
@app.route('/t', methods=['GET'])
def api_decode():
    token = request.args.get('token') or request.args.get("t") or request.args.get("tk")
    if not token: return jsonify({"error": "token required"}), 400
    d = decode_jwt(token); exp = d.get("exp")
    if exp:
        et = dt.datetime.fromtimestamp(exp, tz=timezone.utc)
        expired = et < dt.datetime.now(timezone.utc)
        msg = f"Token {'expired' if expired else 'valid until'} at {et}"
    else:
        et, expired, msg = None, None, "Không có thời gian hết hạn"
    return jsonify({"status": "success", "message": msg, "expired": expired,
                    "exp_time": et.strftime("%Y-%m-%d %H:%M:%S") if et else None,
                    "payload": d, "token": token})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "cached_entries": len(_cache)}), 200


if __name__ == "__main__":
    print("=" * 60)
    print("  FreeFire Guest Login API v6.5 - FINAL")
    print("=" * 60)
    print("[✓] data.token          = access_token (dùng login game / extract)")
    print("[✓] data.refresh_token  = refresh token")
    print("[✓] data.jwt_token      = JWT info (KHÔNG dùng extract)")
    print("[✓] data.open_id        = open_id tài khoản")
    print("[✓] data.account_id     = account_id FF")
    print("[✓] data.nickname       = nickname")
    print("[✓] data.region         = N/A")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)