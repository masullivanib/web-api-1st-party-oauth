"""
Simple test script to demonstrate generating and using a Live Session Token
in a first-party OAuth context. Assumes access token and access token secret
have been generated and stored via IB's nodeJS OAuth demo or OAuth Self-Service 
Portal.

Requires Python packages: pycryptodome, requests

Enter configuration values in Prequisites section below before running.
"""

import json
import requests
import random
import base64
import pprint
from datetime import datetime
from urllib.parse import quote, quote_plus
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1

# List of response headers to print (all others discarded)
RESP_HEADERS_TO_PRINT = ["Content-Type", "Content-Length", "Date", "Set-Cookie", "User-Agent"]

def pretty_request_response(resp: requests.Response) -> str:
    """Print request and response legibly."""
    req = resp.request
    rqh = '\n'.join(f"{k}: {v}" for k, v in req.headers.items())
    rqh = rqh.replace(', ', ',\n    ')
    rqb = f"\n{pprint.pformat(json.loads(req.body))}\n" if req.body else ""
    try:
        rsb = f"\n{pprint.pformat(resp.json())}\n" if resp.text else ""
    except json.JSONDecodeError:
        rsb = resp.text
    rsh = '\n'.join([f"{k}: {v}" for k, v in resp.headers.items() if k in RESP_HEADERS_TO_PRINT])
    return_str = '\n'.join([
        80*'-',
        '-----------REQUEST-----------',
        f"{req.method} {req.url}",
        rqh,
        f"{rqb}",
        '-----------RESPONSE-----------',
        f"{resp.status_code} {resp.reason}",
        rsh,
        f"{rsb}\n",
    ])
    return return_str

# -------------------------------------------------------------------
# Prequisites: Enter paths to keys and access token/secret below
# -------------------------------------------------------------------

# Replace with path to private encryption key file.
with open("./path/to/private_encryption.pem", "r") as f:
    encryption_key = RSA.importKey(f.read())

# Replace with path to private signature key file.
with open("./path/to/private_signature.pem", "r") as f:
    signature_key = RSA.importKey(f.read())

# Replace with path to DH prime PEM file.
with open("./path/to/dhparam.pem", "r") as f:
    dh_param = RSA.importKey(f.read())
    dh_prime = dh_param.n
    dh_generator = dh_param.e  # always =2

# Enter your access token and access token secret here.
access_token = ""
access_token_secret = ""

# If substituting your own consumer key created via the Self-Service Portal,
# change realm to "limited_poa" (test_realm is for TESTCONS only).
consumer_key = "TESTCONS"
realm = "test_realm"

session_object = requests.Session()
live_session_token = None
lst_expiration = None
session_cookie = None

# -------------------------------------------------------------------
# Request #1: Obtaining a LST
# -------------------------------------------------------------------

# Generate a random 256-bit integer.
dh_random = random.getrandbits(256)

# Compute the Diffie-Hellman challenge:
# generator ^ dh_random % dh_prime
# Note that IB always uses generator = 2.
# Convert result to hex and remove leading 0x chars.
dh_challenge = hex(pow(base=dh_generator, exp=dh_random, mod=dh_prime))[2:]

# Generate the base string prepend for the OAuth signature:
# Decrypt the access token secret bytestring using private encryption
# key as RSA key and PKCS1v1.5 padding.
# Prepend is the resulting bytestring converted to hex str.
bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(
    key=encryption_key
    ).decrypt(
        ciphertext=base64.b64decode(access_token_secret), 
        sentinel=None,
        )
prepend = bytes_decrypted_secret.hex()

# Put prepend at beginning of base string str.
base_string = prepend

# Elements of the LST request so far.
method = 'POST'
url = 'https://api.ibkr.com/v1/api/oauth/live_session_token'
oauth_params = {
    "oauth_consumer_key": consumer_key,
    "oauth_nonce": hex(random.getrandbits(128))[2:],
    "oauth_timestamp": str(int(datetime.now().timestamp())),
    "oauth_token": access_token,
    "oauth_signature_method": "RSA-SHA256",
    "diffie_hellman_challenge": dh_challenge,
}

# Combined param key=value pairs must be sorted alphabetically by key
# and ampersand-separated.
params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])

# Base string = method + url + sorted params string, all URL-encoded.
base_string += f"{method}&{quote_plus(url)}&{quote(params_string)}"

# Convert base string str to bytestring.
encoded_base_string = base_string.encode("utf-8")
# Generate SHA256 hash of base string bytestring.
sha256_hash = SHA256.new(data=encoded_base_string)

# Generate bytestring PKCS1v1.5 signature of base string hash.
# RSA signing key is private signature key.
bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(
    rsa_key=signature_key
    ).sign(msg_hash=sha256_hash)

# Generate str from base64-encoded bytestring signature.
b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode("utf-8")

# URL-encode the base64 signature str and add to oauth params dict.
oauth_params['oauth_signature'] = quote_plus(b64_str_pkcs115_signature)

# Oauth realm param omitted from signature, added to header afterward.
oauth_params["realm"] = realm

# Assemble oauth params into auth header value as comma-separated str.
oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])

# Create dict for LST request headers including OAuth Authorization header.
headers = {"Authorization": oauth_header}

# Add User-Agent header, required for all requests. Can have any value.
headers["User-Agent"] = "python/3.11"

# Prepare and send request to /live_session_token, print request and response.
lst_request = requests.Request(method=method, url=url, headers=headers)
lst_response = session_object.send(lst_request.prepare())
print(pretty_request_response(lst_response))

# Check if request returned 200, proceed to compute LST if true, exit if false.
if not lst_response.ok:
    print(f"ERROR: Request to /live_session_token failed. Exiting...")
    raise SystemExit(0)

# Script not exited, proceed to compute LST.
response_data = lst_response.json()
dh_response = response_data["diffie_hellman_response"]
lst_signature = response_data["live_session_token_signature"]
lst_expiration = response_data["live_session_token_expiration"]

# -------------
# Compute LST.
# -------------

# Generate bytestring from prepend hex str.
prepend_bytes = bytes.fromhex(prepend)

# Convert hex string response to integer and compute K=B^a mod p.
# K will be used to hash the prepend bytestring (the decrypted 
# access token) to produce the LST.
a = dh_random
B = int(dh_response, 16)
p = dh_prime
K = pow(B, a, p)

# Generate hex string representation of integer K.
hex_str_K = hex(K)[2:]

# If hex string K has odd number of chars, add a leading 0, 
# because all Python hex bytes must contain two hex digits 
# (0x01 not 0x1).
if len(hex_str_K) % 2:
    print("adding leading 0 for even number of chars")
    hex_str_K = "0" + hex_str_K

# Generate hex bytestring from hex string K.
hex_bytes_K = bytes.fromhex(hex_str_K)

# Prepend a null byte to hex bytestring K if lacking sign bit.
if len(bin(K)[2:]) % 8 == 0:
    hex_bytes_K = bytes(1) + hex_bytes_K

# Generate bytestring HMAC hash of hex prepend bytestring.
# Hash key is hex bytestring K, method is SHA1.
bytes_hmac_hash_K = HMAC.new(
    key=hex_bytes_K,
    msg=prepend_bytes,
    digestmod=SHA1,
    ).digest()

# The computed LST is the base64-encoded HMAC hash of the
# hex prepend bytestring.
# Converted here to str.
computed_lst = base64.b64encode(bytes_hmac_hash_K).decode("utf-8")

# -------------
# Validate LST
# -------------

# Generate hex-encoded str HMAC hash of consumer key bytestring.
# Hash key is base64-decoded LST bytestring, method is SHA1.
hex_str_hmac_hash_lst = HMAC.new(
    key=base64.b64decode(computed_lst),
    msg=consumer_key.encode("utf-8"),
    digestmod=SHA1,
).hexdigest()

# If our hex hash of our computed LST matches the LST signature
# received in response, we are successful.
if hex_str_hmac_hash_lst == lst_signature:
    live_session_token = computed_lst
    lst_expiration = lst_expiration
    print("Live session token computation and validation successful.")
    print(f"LST: {live_session_token} ; expires: {datetime.fromtimestamp(lst_expiration/1000)}\n")
else:
    print(f"ERROR: LST validation failed. Exiting...")
    raise SystemExit(0)
    

# -------------------------------------------------------------------
# Request #2: Using LST to request /portfolio/accounts
# -------------------------------------------------------------------

# Initial, non-computed elements of request to /portfolio/accounts.
method = 'GET'
url = 'https://api.ibkr.com/v1/api/portfolio/accounts'
oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": hex(random.getrandbits(128))[2:],
        "oauth_signature_method": "HMAC-SHA256",
        "oauth_timestamp": str(int(datetime.now().timestamp())),
        "oauth_token": access_token
    }

# ----------------------------------
# Generate request OAuth signature.
# ----------------------------------

# Combined param key=value pairs must be sorted alphabetically by key
# and ampersand-separated.
params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])

# Base string = method + url + sorted params string, all URL-encoded.
base_string = f"{method}&{quote_plus(url)}&{quote(params_string)}"

# Generate bytestring HMAC hash of base string bytestring.
# Hash key is base64-decoded LST bytestring, method is SHA256.
bytes_hmac_hash = HMAC.new(
    key=base64.b64decode(live_session_token), 
    msg=encoded_base_string,
    digestmod=SHA256
    ).digest()

# Generate str from base64-encoded bytestring hash.
b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")

# URL-encode the base64 hash str and add to oauth params dict.
oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)

# Oauth realm param omitted from signature, added to header afterward.
oauth_params["realm"] = realm

# Assemble oauth params into auth header value as comma-separated str.
oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])

# Create dict for LST request headers including OAuth Authorization header.
headers = {"Authorization": oauth_header}

# Add User-Agent header, required for all requests. Can have any value.
headers["User-Agent"] = "python/3.11"

# Prepare and send request to /portfolio/accounts, print request and response.
accounts_request = requests.Request(method=method, url=url, headers=headers)
accounts_response = session_object.send(accounts_request.prepare())
print(pretty_request_response(accounts_response))

# Store web API session cookie value, if it is received.
# (Used when opening websocket.)
if 'api' in accounts_response.cookies.get_dict():
    session_cookie = accounts_response.cookies.get_dict()['api']