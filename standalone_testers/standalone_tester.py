"""
Simple test script to generate LST and make request to /portfolio/accounts.

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

def pretty_request_response(resp: requests.Response) -> str:
    """Helper function to print requests and responses nicely """
    req = resp.request
    req_heads = '\n'.join(f"{k}: {v}" for k, v in req.headers.items()).replace(', ', ',\n    ')
    req_body = f"\n{pprint.pformat(json.loads(req.body))}\n" if req.body else ""
    try:
        resp_body = f"\n{pprint.pformat(resp.json())}\n" if resp.text else ""
    except json.JSONDecodeError:
        resp_body = resp.text
    resp_heads = '\n'.join([f"{k}: {v}" for k,v in resp.headers.items() if k in ("Content-Type", "Content-Length", "Date")])
    return_str = '\n'.join([
        80*'-' + '\n-----------REQUEST-----------',
        f"{req.method} {req.url}\n{req_heads}\n{req_body}",
        '-----------RESPONSE-----------',
        f"{resp.status_code} {resp.reason}\n{resp_heads}\n{resp_body}\n",
    ])
    return return_str

# -------------------------------------------------------------------
# Prequisites: Enter paths to keys and access token/secret below
# -------------------------------------------------------------------

# replace with relative path to private encryption key file
with open("./config/TESTCONS-emuri0718/private_encryption.pem", "r") as f:
    encryption_key = RSA.importKey(f.read())

# replace with relative path to private signature key file
with open("./config/TESTCONS-emuri0718/private_signature.pem", "r") as f:
    signature_key = RSA.importKey(f.read())

# replace with relative path to DH prime
# this expects just the prime by itself, as hex, extracted from pem file via asn1parse,
# as it appears in our node.js demo in the "prime" field at the top.
with open("./config/TESTCONS-emuri0718/dh_prime.txt", "r") as f:
    dh_prime = f.read()

# paste your access token and access token secret here
access_token = "833b7639fa9fec53645d"
access_token_secret = "jT5EuyJ/1UlyydPIAux94cz8SuHu8+t8y2geKtUzrzl4tCJYTTah+A+LyDdwgVA2lZt3LSVQpYn8l7Za2J9M+65U7xVflo5ynyfxv6BERBd//W07SFuT9/9pFHed5D1EBrUMh7sk/yRBHHmSloqPpstg3L4L3T2FhDjGhOSJ0DnlBtlIXyEJSm4jc8rGrvunXx1kCFrwdlpyrEBglCmtG+jfk9nMOhuRD3oiitPNYcMH9zHyQsY1wm6ujclXvjk1guGxIw4bHz0/fLs83IMY3aRPpr4l58cxATfjkI2MyvMNwr6wa9hqwdeJfXH8iOIFTNCNrjWKCW68Mv4yol9epQ=="

consumer_key = "DOMINIONC"
realm = "limited_poa" # test_realm is for TESTCONS only; all others limited_poa

session_object = requests.Session()

live_session_token = None
lst_expiration = None

# -------------------------------------------------------------------
# Request #1: Obtaining a LST
# -------------------------------------------------------------------

# compute DH challenge for /live_session_token request
dh_random = hex(random.getrandbits(256))[2:]
dh_challenge = hex(pow(2, int(dh_random, 16), int(dh_prime, 16)))[2:]

# make prepend for /live_session_token request
access_token_secret_bytes = base64.b64decode(access_token_secret)
cipher = PKCS1_v1_5_Cipher.new(encryption_key)
prepend = cipher.decrypt(access_token_secret_bytes, None).hex()

# build signature base string with prepend for /live_session_token request
base_string = prepend
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
params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
base_string += f"{method}&{quote_plus(url)}&{quote(params_string)}"

# sign signature of /live_session_token request using signature key
signer = PKCS1_v1_5_Signature.new(signature_key)
hash = SHA256.new(base_string.encode("utf-8"))
encoded_signature = base64.encodebytes(signer.sign(hash))
oauth_sig = quote_plus(encoded_signature.decode("utf-8").replace("\n", ""))

# add signature and realm to OAuth header parameters
oauth_params["oauth_signature"] = oauth_sig
oauth_params["realm"] = realm
headers = {"Authorization": "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])}
headers["User-Agent"] = "python-requests/2.31.0"

# send request to /live_session_token
req = requests.Request(method=method, url=url, headers=headers)
response = session_object.send(req.prepare())
print(pretty_request_response(response))

# if response is not 200, print error and exit script
if not response.ok:
    print(f"ERROR: Request to /live_session_token failed. Exiting...")
    raise SystemExit(0)

# proceed to calculate LST if 200 received
response_data = response.json()
dh_response = response_data["diffie_hellman_response"]
lst_signature = response_data["live_session_token_signature"]

# calculate LST
prepend_bytes = [int(byte) for byte in bytearray.fromhex(prepend)]
a = int(dh_random, 16)
B = int(dh_response, 16)
K = pow(B, a, int(dh_prime, 16))
hex_string = hex(K)[2:]
if len(hex_string) % 2 > 0:
    hex_string = "0" + hex_string
byte_array = []
if len(bin(K)[2:]) % 8 == 0:
    byte_array.append(0)
for i in range(0, len(hex_string), 2):
    byte_array.append(int(hex_string[i:i+2], 16))
hmac = HMAC.new(bytes(byte_array), digestmod=SHA1)
hmac.update(bytes(prepend_bytes))
lst = base64.b64encode(hmac.digest()).decode("utf-8")

# validate LST using the lst_signature received
val_hmac = HMAC.new(bytes(base64.b64decode(lst)), digestmod=SHA1)
val_hmac.update(bytes(consumer_key, "utf-8"))
if val_hmac.hexdigest() == lst_signature:
    # validation successful, setting live_session_token and lst_expiration
    live_session_token = lst
    lst_expiration = response_data["live_session_token_expiration"]
    print(f"LST: {live_session_token} ; expires: {datetime.fromtimestamp(lst_expiration/1000)}\n")
else:
    # exit if validation fails
    print(f"ERROR: LST validation failed. Exiting...")
    raise SystemExit(0)
    

# -------------------------------------------------------------------
# Request #2: Using LST to request /portfolio/accounts
# -------------------------------------------------------------------

# make signature base string for request to /portfolio/accounts
method = 'GET'
url = 'https://api.ibkr.com/v1/api/portfolio/accounts'
oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": hex(random.getrandbits(128))[2:],
        "oauth_signature_method": "HMAC-SHA256",
        "oauth_timestamp": str(int(datetime.now().timestamp())),
        "oauth_token": access_token
    }
params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
base_string = f"{method}&{quote_plus(url)}&{quote(params_string)}"

# sign signature for request using LST
hmac = HMAC.new(bytes(base64.b64decode(live_session_token)),digestmod=SHA256)
hmac.update(base_string.encode("utf-8"))
oauth_sig = quote_plus(base64.b64encode(hmac.digest()).decode("utf-8"))

# add signature and realm to OAuth header parameters
oauth_params["oauth_signature"] = oauth_sig
oauth_params["realm"] = realm
headers = {"Authorization": "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])}
headers["User-Agent"] = "python-requests/2.31.0"

# send request to /portfolio/accounts
req = requests.Request(method=method, url=url, headers=headers)
response = session_object.send(req.prepare())
print(pretty_request_response(response))
