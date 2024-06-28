"""
Simple test script to demonstrate generating and using a Live Session Token
in a first-party OAuth context. Assumes access token and access token secret
have been generated and stored via IB's nodeJS OAuth demo or OAuth Self-Service 
Portal.

Requires Python packages: pycryptodome, requests

Enter configuration values in Prequisites section below before running.
"""

from typing import Callable
import json
import requests
import random
import base64
from datetime import datetime
from urllib.parse import quote, quote_plus, unquote
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1


# -------------------------------------------------------------------
# Prequisites: Enter paths to keys and access token/secret below
# -------------------------------------------------------------------
CONSUMER_KEY = "TESTCONS"
PATH_TO_PRIVATE_ENCRYPTION_PEM = "C:\\Users\\ms186\\IBKR\\Projects\\OAuth-Python\\consumers\\TESTCONS\\TESTCONS_private_encryption.pem"
PATH_TO_PRIVATE_SIGNATURE_PEM = "C:\\Users\\ms186\\IBKR\\Projects\\OAuth-Python\\consumers\\TESTCONS\\TESTCONS_private_signature.pem"
PATH_TO_DH_PARAM_PEM = "C:\\Users\\ms186\\IBKR\\Projects\\OAuth-Python\\consumers\\TESTCONS\\TESTCONS_dhparam.pem"

ACCESS_TOKEN = "c4b6c8ac0a16a8f40f76"
ACCESS_TOKEN_SECRET = "vpWuGMnoacufJYIl0yxcJVq39wknffD5TR+Y2gaQdyll2wAn25v+gRndZEnzsIMEEpIMlJA370s6Z453mrvsaxdL/umT++H51UwWQ958UcTkdVkFkv6lrHEkpVy1af1jHoBdxfukjCXM7KnCy4EKYpKdTIr2DkTN/+5PuZp0zBdrIVFZV9sdialmJ30zjqQ6uWsSAiZ402nCHV7gboNE3bP1UlLVO40AdLQrihhoDt9Ync3OHok+psZoQfLMotbHw0d/gEZkFjmMHT+XaqG5NNfoSXofgvVMqo1EpJj20U4Kv5+y2jR/OIQeshq1pxKTejpX6PuTydkZ8PMltXaRww=="


def main():
    with open(PATH_TO_PRIVATE_ENCRYPTION_PEM, "r") as f:
        encryption_key = RSA.importKey(f.read())
    with open(PATH_TO_PRIVATE_SIGNATURE_PEM, "r") as f:
        signature_key = RSA.importKey(f.read())
    with open(PATH_TO_DH_PARAM_PEM, "r") as f:
        dh_params = RSA.importKey(f.read())
        dh_prime = dh_params.n
        dh_generator = dh_params.e  # always =2
    realm = "test_realm" if CONSUMER_KEY == "TESTCONS" else "limited_poa"

    live_session_token = None
    lst_expiration = None
    session_cookie = None

    domain = "api.ibkr.com"
    environment = "/v1/api"  # Production, or "/alpha/api" for Alpha test env
    base_url = domain + environment

    base_headers = {"User-Agent": "python/3.11"}

    # --------------------------------------------------------------------------

    live_session_token, lst_expiration = request_live_session_token(
        base_url=base_url,
        base_headers=base_headers,
        consumer_key=CONSUMER_KEY,
        realm=realm,
        encryption_key=encryption_key,
        signature_key=signature_key,
        dh_prime=dh_prime,
        dh_generator=dh_generator,
        access_token=ACCESS_TOKEN,
        access_token_secret=ACCESS_TOKEN_SECRET,
    )

    # --------------------------------------------------------------------------

    authorized_request = build_authorized_request(
        base_url=base_url,
        base_headers=base_headers,
        consumer_key=CONSUMER_KEY,
        realm=realm,
        live_session_token=live_session_token,
        access_token=ACCESS_TOKEN,
    )

    authorized_request('GET', '/portfolio/accounts')

    authorized_request('POST', '/iserver/auth/ssodh/init', body={"publish": True, "compete": True})

    authorized_request('GET', '/iserver/accounts')

    authorized_request('POST', '/tickle')


def request_live_session_token(
    base_url: str,
    base_headers: dict,
    consumer_key: str,
    realm: str,
    encryption_key: RSA.RsaKey,
    signature_key: RSA.RsaKey,
    dh_prime: int,
    dh_generator: int,
    access_token: str,
    access_token_secret: str,
) -> tuple[str, int]:
    # Generate a random 256-bit integer.
    dh_random = random.getrandbits(256)

    # Compute the Diffie-Hellman challenge:
    # generator ^ dh_random % dh_prime
    # Note that IB always uses generator = 2.
    # Convert result to hex and remove leading 0x chars.
    dh_challenge = hex(pow(base=dh_generator, exp=dh_random, mod=dh_prime))[2:]

    # --------------------------------
    # Generate LST request signature.
    # --------------------------------

    # Generate the base string prepend for the OAuth signature:
    # Decrypt the access token secret bytestring using private encryption
    # key as RSA key and PKCS1v1.5 padding.
    # Prepend is the resulting bytestring converted to hex str.
    bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(key=encryption_key).decrypt(
        ciphertext=base64.b64decode(access_token_secret),
        sentinel=None,
    )
    prepend = bytes_decrypted_secret.hex()

    # Put prepend at beginning of base string str.
    base_string = prepend
    # Elements of the LST request so far.
    method = "POST"
    url = f"https://{base_url}/oauth/live_session_token"
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
    bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(rsa_key=signature_key).sign(
        msg_hash=sha256_hash
    )

    # Generate str from base64-encoded bytestring signature.
    b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode(
        "utf-8"
    )

    # URL-encode the base64 signature str and add to oauth params dict.
    oauth_params["oauth_signature"] = quote_plus(b64_str_pkcs115_signature)

    # Oauth realm param omitted from signature, added to header afterward.
    oauth_params["realm"] = realm

    # Assemble oauth params into auth header value as comma-separated str.
    # Note that values are wrapped in double quotes, while keys are not.
    oauth_header = "OAuth " + ", ".join(
        [f'{k}="{v}"' for k, v in sorted(oauth_params.items())]
    )

    # Create dict for LST request headers including OAuth Authorization header.
    headers = {"Authorization": oauth_header}

    # Add User-Agent header, required for all requests. Can have any value.
    headers["User-Agent"] = "python/3.11"

    # Prepare and send request to /live_session_token, print request and response.
    lst_response = requests.request(method=method, url=url, headers=headers)
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
        print(
            f"LST: {live_session_token}; expires: {datetime.fromtimestamp(lst_expiration/1000)}\n"
        )
    else:
        print(f"ERROR: LST validation failed. Exiting...")
        raise SystemExit(0)

    return live_session_token, lst_expiration


def build_authorized_request(
    base_url: str,
    base_headers: dict,
    consumer_key: str,
    realm: str,
    live_session_token: str,
    access_token: str,
) -> Callable:
    def authorized_request(
        method: str,
        path: str,
        body: dict = None,
    ) -> requests.Response:  
        url = f"https://{base_url}{path}"

        query_params = {}
        if '?' in path:
            resource_path, query_params_string = path.split('?')
            for qp in query_params_string.split('&'):
                k, v = qp.split('=')
                query_params[k] = v
            bare_url = f"https://{base_url}{resource_path}"
        else:
            bare_url = url
        
        oauth_params = {
            "oauth_consumer_key": consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": access_token,
        }

        signature_params = oauth_params | query_params

        # ----------------------------------
        # Generate request OAuth signature.
        # ----------------------------------

        # Combined param key=value pairs must be sorted alphabetically by key
        # and ampersand-separated.
        params_string = "&".join([f"{k}={v}" for k, v in sorted(signature_params.items())])

        # Base string = method + url + sorted params string, all URL-encoded.
        signature_base_string = f"{method}&{quote_plus(bare_url)}&{quote(params_string)}"

        # Generate bytestring HMAC hash of base string bytestring.
        # Hash key is base64-decoded LST bytestring, method is SHA256.
        hmac_hash_bytes = HMAC.new(
            key=base64.b64decode(live_session_token),
            msg=signature_base_string.encode("utf-8"),
            digestmod=SHA256,
        ).digest()

        # Generate str from base64-encoded bytestring hash.
        b64_hmac_hash_string = base64.b64encode(hmac_hash_bytes).decode("utf-8")

        # URL-encode the base64 hash str and add to oauth params dict.
        oauth_params["oauth_signature"] = quote_plus(b64_hmac_hash_string)

        # Oauth realm param omitted from signature, added to auth header value afterward.
        oauth_params["realm"] = realm

        # Assemble oauth params into auth header value as comma-separated str.
        auth_header_value_string = "OAuth " + ", ".join(
            [f'{k}="{v}"' for k, v in sorted(oauth_params.items())]
        )

        # Create dict for request headers including OAuth Authorization header.
        headers = base_headers | {"Authorization": auth_header_value_string}

        response = requests.request(method=method, url=url, headers=headers, json=body)
        print(pretty_request_response(response))
        return response

    return authorized_request




def pretty_request_response(resp: requests.Response) -> str:
    """Print request and response legibly."""
    def jsonner (obj, depth: int) -> str:
        if isinstance(obj, str): return f"\"{obj}\""
        if isinstance(obj, (int, float, bool)): return str(obj).lower()
        if obj is None: return 'null'
        outstr, idt, max_w, n_items, is_dict = '', 2, 70, len(obj), isinstance(obj, dict)
        for i in range(0, n_items):
            k, v = (lambda x, y: (f"\"{x}\": ", y))(*list(obj.items())[i]) if is_dict else ('', obj[i])
            outstr += f"{(depth + 1)*idt*' '}{k}{jsonner(v, depth + 1)}{',\n'*(i != n_items - 1)}"
        outstr = f"{'[{'[is_dict]}\n{outstr}\n{depth*idt*' '}{']}'[is_dict]}"
        return " ".join(s.strip() for s in outstr.split("\n")) if len(outstr) < max_w else outstr
    
    tstamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    req = resp.request
    rqm, rqu = req.method, req.url
    rqh = '\n'.join([f"{k}: {v}" for k, v in req.headers.items() if k in [
        "User-Agent", "Content-Length", "Cookie", "Authorization"
    ]]).replace(', ', ',\n    ')
    rqb = f"\n{jsonner(json.loads(req.body), 0)}\n" if req.body else ""
    req_str = f"{tstamp} REQUEST\n{rqm} {unquote(rqu)}\n{rqh}\n{rqb}"

    rsc, rsr = resp.status_code, resp.reason
    rsh = '\n'.join([f"{k}: {v}" for k, v in resp.headers.items() if k in [
        "Content-Type", "Content-Length", "Date", "Set-Cookie", "User-Agent"
    ]])
    rtt = f"elapsed={round(resp.elapsed.total_seconds()*1000, 3)}\n"
    try:
        rsb = f"\n{jsonner(resp.json(), 0)}\n" if resp.text else ""
    except json.JSONDecodeError:
        rsb = resp.text
    resp_str = f"{tstamp} RESPONSE {rtt}{rsc} {rsr}\n{rsh}\n{rsb}\n"
    return f"{req_str}\n{resp_str}"

if __name__ == "__main__":
    main()
