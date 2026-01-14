from flask import Flask, request, jsonify
import requests, json

app = Flask(__name__)

# دالة get_login_data
def get_login_data(JWT_TOKEN, PAYLOAD):
    url = "https://clientbp.ggblueshark.com/GetLoginData"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB52',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Expect': '100-continue',
        'Authorization': f'Bearer {JWT_TOKEN}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'X-GA': 'v1 2',
        'Accept-Encoding': 'gzip'
    }

    try:
        response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
        response.raise_for_status()
        x = response.content.hex()

        # Lưu ý: Hàm get_available_room bị thiếu ở đây.
        json_result = "{}"   # Bộ đếm thời gian trống để máy chủ không bị sập
        parsed_data = json.loads(json_result)

        return parsed_data
    except Exception as e:
        return {"error": str(e)}

@app.route("/get/asses", methods=["GET"])
def guest_token():
    uid = request.args.get("uid")
    password = request.args.get("password")

    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    payload = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }

    response = requests.post(url, headers=headers, data=payload)
    return jsonify(response.json())

if __name__ == "__main__":
    app.run(debug=True, port=5000)
