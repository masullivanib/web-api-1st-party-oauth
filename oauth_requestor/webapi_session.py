import json
import requests
import random
import base64
import pprint
import websocket
from threading import Thread
from datetime import datetime
from time import time, ctime
from urllib.parse import quote, quote_plus
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1


class WebAPISession:
    """Class to handle web API session with authentication via OAuth."""

    def __init__(
        self,
        config_path: str,
        init_brokerage: bool = True,
        logging: bool = True,
        verbose: bool = True,
        domain: str = 'api.ibkr.com',
        env: str = 'v1'
    ):
        self.logging, self.verbose = logging, verbose
        self.config_path = config_path
        self.domain = domain
        self.env = env
        self.session_object = requests.Session()
        self.websocket = None
        self.ws_thread = None

        for k, v in read_in_config(config_path).items():
            setattr(self, k, v)

        self.log_path = f"{self.log_dir}/{datetime.now().strftime('%Y-%m-%d')}_log.txt"

        if not self.live_session_token or self.__is_lst_expiring(self.lst_expiration):
            self.get_live_session_token()
        else:
            print(f"Valid LST found: {self.live_session_token} expires {ctime(self.lst_expiration/1000)}\n")
        if init_brokerage:
            self.init_brokerage_session(verbose=False)

    def __is_lst_expiring(self, lst_expiration: int) -> bool:
        """Tests whether the current time is within 10 minutes of the stored
        LST expiration time. (10 mins = 600000 milliseconds)

        Parameters:
            lst_expiration (int): Unix epoch timestamp of LST's expiration 
            in milliseconds
        Returns:
            bool: True if LST is 10 minutes from expiration, False otherwise
        """
        if lst_expiration - int(time()*1000) < 600000:
            return True
        else:
            return False

    def __make_auth_header(
            self,
            method: str,
            url: str,
            query_params: dict = None,
            dh_challenge: str = None,
            prepend: str = None,
        ) -> dict:
        """Builds the Authorization header string for any request, before or
        after obtaining a LST.

        Parameters:
            method (str): request's HTTP method
            url (str): request's base URL without query params
            query_params (dict): key-value pairs of request's query params
            dh_challenge (str): LST request's Diffie-Hellman challenge value
            prepend (str): LST request's signature prepend value
        Returns:
            dict: Single key pair, {"Authorization": "OAuth PARAMS_STRING"}
        """

        # String of request elements from which we will generate signature.
        base_string = ""

        # Default oauth params for any request post-LST.
        oauth_params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": self.access_token
        }

        # If prepend not None, this is a LST request, so we change the
        # signature method, add the DH challenge, and put the prepend string
        # at the beginning of the base string.
        if prepend is not None:
            oauth_params["oauth_signature_method"] = "RSA-SHA256"
            oauth_params["diffie_hellman_challenge"] = dh_challenge
            base_string += prepend

        # Base string includes all oauth params in the Authorization header
        # as well as all query params in the request.
        params_dict = oauth_params if query_params is None else {**oauth_params, **query_params}

        # Combined param key=value pairs must be sorted alphabetically by key
        # and ampersand-separated.
        params_string = "&".join([f"{k}={v}" for k, v in sorted(params_dict.items())])

        # Base string = method + url + sorted params string, all URL-encoded.
        base_string += f"{method}&{quote_plus(url)}&{quote(params_string)}"

        # Convert base string str to bytestring.
        encoded_base_string = base_string.encode("utf-8")


        # OAuth signature is generated from base string in a different manner 
        # for pre-LST requests compared to post-LST requests. 
        # Here we test whether a prepend string has been supplied to determine
        # whether this is a pre- or post-LST request.
        # Prepend present = requesting LST = base string is signed with
        # the private signature key using method RSA-SHA256.
        # No prepend = have LST, making any other request, base string is 
        # signed with the LST using method HMAC-SHA256.
        if prepend is not None:

            # Generate SHA256 hash of base string bytestring.
            sha256_hash = SHA256.new(data=encoded_base_string)

            # Generate bytestring PKCS1v1.5 signature of base string hash.
            # RSA signing key is private signature key.
            bytes_pkcs115_signature = PKCS1_v1_5_Signature.new(
                rsa_key=self.signature_key
                ).sign(msg_hash=sha256_hash)
            
            # Generate str from base64-encoded bytestring signature.
            b64_str_pkcs115_signature = base64.b64encode(bytes_pkcs115_signature).decode("utf-8")

            # URL-encode the base64 signature str and add to oauth params dict.
            oauth_params['oauth_signature'] = quote_plus(b64_str_pkcs115_signature)

        else:

            # Generate bytestring HMAC hash of base string bytestring.
            # Hash key is base64-decoded LST bytestring, method is SHA256.
            bytes_hmac_hash = HMAC.new(
                key=base64.b64decode(self.live_session_token), 
                msg=encoded_base_string,
                digestmod=SHA256
                ).digest()
            
            # Generate str from base64-encoded bytestring hash.
            b64_str_hmac_hash = base64.b64encode(bytes_hmac_hash).decode("utf-8")

            # URL-encode the base64 hash str and add to oauth params dict.
            oauth_params["oauth_signature"] = quote_plus(b64_str_hmac_hash)

        # Oauth realm param omitted from signature, added to header afterward.
        oauth_params["realm"] = self.realm

        # Assemble oauth params into auth header value as comma-separated str.
        oauth_header = "OAuth " + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])

        # Return Authorization: OAuth header as dict.
        return {"Authorization": oauth_header}
    
    def get_live_session_token(self, verbose=False) -> None:
        """Constructs and sends request to /live_session_token endpoint.
        If request is successful, computes LST from the returned DH response, 
        validates computed LST against the returned LST signature, and caches
        the newly-created LST and expiration for use with future requests.

        Parameters:
            verbose (bool): Controls print output to stdout, passed through
            to __send_request() method
        Returns:
            None
        """
        method = "POST"
        url = f"https://{self.domain}/{self.env}/api/oauth/live_session_token"

        # Generate a random 256-bit integer.
        dh_random = random.getrandbits(256)

        # Compute the Diffie-Hellman challenge:
        # generator ^ dh_random % dh_prime
        # Note that IB always uses generator = 2.
        # Convert result to hex and remove leading 0x chars.
        dh_challenge = hex(pow(base=self.dh_generator, exp=dh_random, mod=self.dh_prime))[2:]

        # Generate the base string prepend for the OAuth signature:
        # Decrypt the access token secret bytestring using private encryption
        # key as RSA key and PKCS1v1.5 padding.
        # Prepend is the resulting bytestring converted to hex str.
        bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(
            key=self.encryption_key
            ).decrypt(
                ciphertext=base64.b64decode(self.access_token_secret), 
                sentinel=None,
                )
        prepend = bytes_decrypted_secret.hex()

        # Use DH challenge and prepend to generate LST request Auth header.
        auth_header = self.__make_auth_header(method, url, None, dh_challenge, prepend)

        # Send request to /live_session_token and handle response.
        lst_response = self.__send_request(
            verbose=verbose, 
            method=method,
            url=url,
            headers=auth_header,
            )
        if not lst_response.ok:
            print(f"ERROR: Request to /live_session_token failed. Exiting...")
            raise SystemExit(0)
        else:
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
            p = self.dh_prime
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
                msg=self.consumer_key.encode("utf-8"),
                digestmod=SHA1,
            ).hexdigest()

            # If our hex hash of our computed LST matches the LST signature
            # received in response, we are successful.
            if hex_str_hmac_hash_lst == lst_signature:
                self.live_session_token = computed_lst
                self.lst_expiration = lst_expiration
                write_lst(self.lst_cache_fp, computed_lst, lst_expiration)
                print(f"Generated new LST: {computed_lst} expires {ctime(lst_expiration/1000)}\n")
            else:
                print(f"ERROR: LST validation failed. Exiting...")
                raise SystemExit(0)
            
    def __send_request(
            self, 
            verbose: bool = None, 
            **kwargs,
        ) -> requests.Response:
        """Helper method to dispatch, print, and log arbitrary HTTP requests.
        
        Parameters:
            verbose (bool): True prints complete request and response, 
                False prints only request URL and response status
            **kwargs (Any): Elements of the request
        Returns:
            requests.Response object
        """
        verbose = self.verbose if verbose is None else verbose
        req = requests.Request(**kwargs)
        response = self.session_object.send(req.prepare(), allow_redirects=False)

        if 'api' in response.cookies.get_dict():
            self.api_session = response.cookies.get_dict()['api']
            write_session(self.session_cache_fp, self.api_session, int(time()*1000))

        pretty_out_str = pretty_request_response(response)
        if verbose:
            print(pretty_out_str)
        else:
            print(f"REQUEST: {response.request.method} {response.request.url}")
            print(f"RESPONSE: {response.status_code} {response.reason}\n")
        if self.logging:
            with open(self.log_path, 'a') as f: 
                f.write(pretty_out_str)
        return response

    def request(
            self,
            method: str,
            path: str,
            body: dict = None,
            headers: dict = {},
            domain: str = None,
            env: str = None,
            verbose: bool = None,
        ) -> dict | str:
        """Method for making all post-LST requests. Assembles all elements of
        request. First calls __is_lst_expiring() to test age of cached LST and
        obtain new LST if nearing expiration. Then contructs headers dict with
        call to __make_auth_header() for OAuth Authorization header. Adds 
        Cookie header if cached session value exists. Calls __send_request()
        to dispatch and receives requests.Response object back.
        
        Parameters:
            method (str): Request's HTTP method
            path (str): Request's URI path
            body (dict): Request's JSON payload
            headers (dict): Manually supplied headers for request
            domain (str): IB domain for request
            env (str): Web API environment (v1 or alpha)
            verbose (bool): Controls print output to stdout, passed through
            to __send_request() method
        Returns:
            dict | str: Response's JSON body dict returned if it exists,
            otherwise Response.text, which also covers failed requests
        """
        domain = self.domain if domain is None else domain
        env = self.env if env is None else env

        # before attempting request, first check stored LST's expiration
        # only obtain new LST if close to expiration
        if self.__is_lst_expiring(self.lst_expiration):
            self.get_live_session_token()

        # User-Agent header required for all requests
        req_headers = {'User-Agent': 'python/3.11'}

        # only add a Cookie header for API session if we have one stored
        if self.api_session:
            req_headers['Cookie'] = f"api={self.api_session}"

        method = method.upper()

        query_params_dict = {}
        if '?' in path:
            base_uri, query_params_str = path.split('?')
            query_params_list = query_params_str.split('&')
            for qp in query_params_list:
                if '=' in qp:
                    k, v = qp.split('=')
                    query_params_dict[k] = v
        else:
            base_uri = path

        url = f"https://{domain}/{env}/api{base_uri}"

        auth_header = self.__make_auth_header(method, url, query_params_dict)
        # add Authorization header to dict of request's headers
        req_headers.update(auth_header)
        # let manually supplied headers overwrite defaults
        req_headers.update(headers)

        response = self.__send_request(
            verbose=verbose,
            method=method,
            url=url,
            headers=req_headers,
            params=query_params_dict,
            json=body,
            )
        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text

    def init_brokerage_session(
            self, 
            compete: bool = True, 
            publish: bool = True,
            renew: bool = False,
            verbose: bool = False,
        ) -> dict | str:
        """Method specifically for making request to /iserver/auth/ssodh/init
        for opening brokerage session. This method is for convenience, and
        this request is no different from any other post-LST request. Calls
        request() method.
        
        Parameters:
            compete (bool): Request query param, must be True
            publish (bool): Request query param, must be True
            renew (bool): Forces this method to open a new brokerage session
            without first testing if one exists
            verbose (bool): Controls print output to stdout, passed through
            to __send_request() method
        Returns:
            dict | str: Passes through request() method's return value, either
            Response's JSON body dict or Response.text
        """
        if renew:
            auth_status = False
            print_mask = 'Force-renew brokerage session: authenticated={}\n'
        else:
            response = self.request(
                "POST", 
                "/iserver/auth/status", 
                verbose=verbose,
                )
            auth_status = response["authenticated"]
            
        if auth_status:
            print_mask = 'Brokerage session already exists: authenticated={}\n'
        else:
            params = f"publish={publish}&compete={compete}".lower()
            response = self.request(
                "POST", 
                f"/iserver/auth/ssodh/init?{params}", 
                verbose=verbose,
                )
            if isinstance(response, dict):
                auth_status = response["authenticated"]
                if bool(auth_status):
                    print_mask = 'Opened brokerage session: authenticated={}\n'
                else:
                    print_mask = 'Failed to open brokerage session: authenticated={}\n'
            else:
                auth_status = response
                print_mask = 'Request to /iserver/auth/ssodh/init failed: {}\n'

        print(print_mask.format(auth_status))
        return response
        
    def open_websocket(
            self, 
            verbose: bool = False,
            ) -> dict | str:
        self.ws_thread = Thread(target=self.__run_websocket)
        self.ws_thread.start()

    def __run_websocket(self, verbose: bool = False,) -> dict | str:
        session = self.request("POST", "/tickle", verbose=False)["session"]
        ws_url = f"wss://api.ibkr.com/v1/api/ws?oauth_token={self.access_token}"
        self.websocket = websocket.WebSocketApp(
            url=ws_url,
            on_error=self.__ws_on_error,
            on_close=self.__ws_on_close,
            on_message=self.__ws_on_message, 
            header=["User-Agent: python/3.11"],
            cookie=f"api={session}",
            )
        self.websocket.on_open = self.__ws_on_open
        self.websocket.run_forever()

    def send_ws(self, message: str):
        print(
            datetime.now().strftime("%H:%M:%S.%f")[:-3],
            f"<- WS SEND: {message}\n", 
            )
        self.websocket.send(message)

    def __ws_on_open(self, websocket):
        print("Websocket open.")

    def __ws_on_error(self, websocket, error):
        print(error)

    def __ws_on_close(self, websocket, close_status_code, close_msg):
        print("Websocket closed.")

    def __ws_on_message(self, websocket, message):
        print(
            datetime.now().strftime("%H:%M:%S.%f")[:-3],
            f"-> WS RECV: {message.decode('utf-8')}\n", 
            )
        
# ----------------------------------------------------------------------------

# List of response headers to print (all others discarded)
RESP_HEADERS_TO_PRINT = ["Content-Type", "Content-Length", "Date", "Set-Cookie", "User-Agent"]

def pretty_request_response(resp: requests.Response) -> str:
    """Print request and response legibly when verbose=True. 
    Also used for logging.
    """
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

def read_in_config(config_path: str) -> dict:
    """Read in fixed authentication keys/tokens from files."""
    try:
        with open(f"{config_path}/config.json", "r") as f:
            session_dict = json.load(f)
        assert all(k in session_dict for k in ("consumer_fp", "access_fp", "lst_cache_fp", "session_cache_fp", "log_dir"))
        for k, v in session_dict.items():
            session_dict[k] = f"{config_path}{v[1:]}" if v[:2] == './' else v

        with open(session_dict.pop("consumer_fp"), "r") as f:
            consumer_dict = json.load(f)
        assert all(k in consumer_dict for k in ("consumer_key", "encryption_key_fp", "signature_key_fp", "dhparam_fp"))
        session_dict["consumer_key"] = consumer_dict.pop("consumer_key")
        for k, v in consumer_dict.items():
            consumer_dict[k] = f"{config_path}{v[1:]}" if v[:2] == './' else v
        with open(consumer_dict['encryption_key_fp'], "r") as f:
            session_dict["encryption_key"] = RSA.importKey(f.read())
        with open(consumer_dict['signature_key_fp'], "r") as f:
            session_dict["signature_key"] = RSA.importKey(f.read())
        with open(consumer_dict['dhparam_fp'], "r") as f:
            dh_param = RSA.importKey(f.read())
            session_dict["dh_prime"] = dh_param.n
            session_dict["dh_generator"] = dh_param.e  # always =2

        with open(session_dict.pop("access_fp"), "r") as f:
            session_dict.update(json.load(f))
        assert all(k in session_dict for k in ("access_token", "access_token_secret"))

        session_dict["realm"] = "test_realm" if session_dict["consumer_key"] == "TESTCONS" else "limited_poa"

        with open(session_dict["lst_cache_fp"], "r") as f:
            session_dict.update(json.load(f))
        with open(session_dict["session_cache_fp"], "r") as f:
            session_dict.update(json.load(f))
        return session_dict
    except (OSError, KeyError, AssertionError) as e:
        print(e)
        print("Exiting...")
        raise SystemExit(0)
    
def write_lst(lst_cache_fp: str, lst: str, lst_expiration: str) -> None:
    """Cache computed LST and expiration timestamp in JSON text file."""
    lst_cache = {"live_session_token": lst, "lst_expiration": lst_expiration}
    try:
        with open(lst_cache_fp, "w") as f:
            json.dump(lst_cache, f)
    except OSError as e:
        print(e)

def write_session(session_cache_fp: str, sesh: dict, sesh_updated: str) -> None:
    """Cache web API session cookie value and timestamp in JSON text file."""
    session_cache = {"api_session": sesh, "api_session_updated": sesh_updated}
    try:
        with open(session_cache_fp, "w") as f:
            json.dump(session_cache, f)
    except OSError as e:
        print(e)