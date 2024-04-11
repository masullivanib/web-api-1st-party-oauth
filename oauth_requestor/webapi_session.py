import json
import requests
import random
import base64
import pprint
import websocket
import threading
from pathlib import Path
from datetime import datetime
from time import time, ctime
from urllib.parse import quote, quote_plus, unquote
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1

get, post, delete, put = "get", "post", "delete", "put"

class WebAPIConsumer:
    """Class to handle web API session with authentication via OAuth."""

    def __init__(
        self,
        *,
        init_brokerage: bool = True,
        verbose: bool = True,
        print_all_headers: bool = False,
        logging: bool = True,
        log_path: str = "",
        domain: str = 'api.ibkr.com',
        env: str = 'v1/api',
        consumer_key: str,
        encryption_key: bytes,
        signature_key: bytes,
        dhparam: bytes,
        access_token: str,
        access_token_secret: str,
        live_session_token: str = "",
        lst_expiration: int = 0,
        session_cookie: str = "",
        session_cookie_updated: int = 0,
        session_cache_path: str
    ):
        self.execution_start_time = int(time()*1000)
        self.first_request_flag = True
        
        self.session_object = requests.Session()
        self.user_agent = "python/3.11"
        self.websocket = None
        self.ws_thread = None
        self.ws_open_flag = threading.Event()
        self.ws_msg_method = None

        self.domain, self.env = domain, env
        self.logging, self.verbose = logging, verbose
        self.headers_to_print = lambda rhs: rhs & {
            "Content-Type", 
            "Content-Length", 
            "Date", 
            "Set-Cookie"
        } if not print_all_headers else rhs

        self.consumer_key = consumer_key
        self.access_token = access_token
        self.access_token_secret = access_token_secret
        self.realm = "test_realm" if consumer_key == "TESTCONS" else "limited_poa"

        try:
            self.encryption_key = RSA.importKey(encryption_key)
            self.signature_key = RSA.importKey(signature_key)
            self.dhparam = RSA.importKey(dhparam)
        except (ValueError, IndexError) as e:
            print(f"{e}\n{{}}\nExiting...".format(
                "Ensure that the provided key data bytestrings are valid, \
                    PEM-encoded RSA keys."
            ))
            raise SystemExit(0)
        
        try:
            self.session_cache_path = Path(session_cache_path).resolve(strict=False)
            self.session_cache_path.touch(exist_ok=True)
            if self.logging:
                self.log_path = Path(log_path).resolve(strict=False)
                self.log_path.touch(exist_ok=True)
        except (OSError, ValueError) as e:
            print(f"{e}\nExiting...")
            raise SystemExit(0)

        self.live_session_token = live_session_token
        self.lst_expiration = lst_expiration
        self.session_cookie = session_cookie
        self.session_cookie_updated = session_cookie_updated

        if not live_session_token or self.__is_lst_expiring(lst_expiration):
            self.get_live_session_token()
        else:
            self.live_session_token = live_session_token
            self.lst_expiration = lst_expiration
            print("***Valid LST found: {} expires {}\n".format(
                self.live_session_token,
                ctime(self.lst_expiration/1000)
            ))

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
        oauth_header = "OAuth " + ", ".join(
            [f'{k}="{v}"' for k, v in sorted(oauth_params.items())]
        )

        # Return Authorization: OAuth header as dict.
        return {"Authorization": oauth_header}
    
    def get_live_session_token(self, verbose=True) -> None:
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
        url = f"https://{self.domain}/{self.env}/oauth/live_session_token"

        # Generate a random 256-bit integer.
        dh_random = random.getrandbits(256)

        # Compute the Diffie-Hellman challenge:
        # generator ^ dh_random % dhparam.n
        # Note that IB always uses generator = 2 (dhparam.e).
        # Convert result to hex and remove leading 0x chars.
        dh_challenge = hex(pow(base=self.dhparam.e, exp=dh_random, mod=self.dhparam.n))[2:]

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
            p = self.dhparam.n
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
                self.__write_session_cache()
                print(f"Generated new LST: {computed_lst} expires {ctime(lst_expiration/1000)}\n")
            else:
                print(f"ERROR: LST validation failed. Exiting...")
                raise SystemExit(0)

    def __write_session_cache(self) -> None:
        self.session_cache_path.write_text(json.dumps({
                'live_session_token': self.live_session_token,
                'lst_expiration': self.lst_expiration,
                'session_cookie': self.session_cookie,
                'session_cookie_updated': self.session_cookie_updated,
            }
        ))

    def __send_request(
            self, 
            verbose: bool, 
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
        req = requests.Request(**kwargs).prepare()
        self.__print_and_log_request(req=req, verbose=verbose, logging=self.logging)
        resp = self.session_object.send(req, allow_redirects=False)
        self.__print_and_log_response(resp=resp, verbose=verbose, logging=self.logging)
        if 'api' in resp.cookies.get_dict():
            self.session_cookie = resp.cookies.get_dict()['api']
            self.session_cookie_updated = int(time()*1000)
            self.__write_session_cache()
        return resp

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
        if self.session_cookie:
            req_headers['Cookie'] = f"api={self.session_cookie}"

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

        url = f"https://{domain}/{env}{base_uri}"

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
        if response.status_code == 401 and self.first_request_flag:
            self.get_live_session_token(verbose)
            self.first_request_flag = False
            self.request(method, path, body, headers, domain, env, verbose)
        else:
            response_return = {
                "status": response.status_code,
                "reason": response.reason,
                "obj": response
            }
            try:
                response_return["body"] = response.json()
            except json.JSONDecodeError:
                response_return["body"] = response.text
            return response_return

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
            print_mask = '***Force-renew brokerage session: authenticated={}\n'
        else:
            response = self.request(
                "POST", 
                "/iserver/auth/status", 
                verbose=verbose,
                )
            auth_status = response["body"]["authenticated"]
            # auth_status = False

        if auth_status:
            print_mask = '***Brokerage session already exists: authenticated={}\n'
        else:
            params = f"publish={publish}&compete={compete}".lower()
            response = self.request(
                "GET", 
                f"/iserver/auth/ssodh/init?{params}", 
                verbose=verbose,
                )
            # print(response.json())
            if isinstance(response["body"], dict):
                auth_status = response["body"]["authenticated"]
                if bool(auth_status):
                    print_mask = '***Opened brokerage session: authenticated={}\n'
                else:
                    print_mask = '***Failed to open brokerage session: authenticated={}\n'
            else:
                auth_status = f"{response['status']} {response['reason']} {response['body']}"
                print_mask = '***Request to /iserver/auth/ssodh/init failed: {}\n'

        print(print_mask.format(auth_status))
        return response
    
    def open_websocket(
            self,
            method = None, 
            get_cookie: bool = True,
            verbose: bool = False,
            ) -> dict | str:
        if get_cookie:
            self.get_session_cookie(verbose)
        self.ws_msg_method = method
        self.ws_thread = threading.Thread(target=self.__run_websocket, args=[verbose])
        self.ws_thread.start()

    def send_websocket(
            self, 
            message: str = "",
        ) -> bool:
        def __thread_send(message: str):
            self.ws_open_flag.wait()
            if message[-1] == '+':
                message = message + '{}'
            message = message.replace("'", '"').replace(' ', '')
            self.__print_and_log_ws_message(recv=False, msg=message, logging=self.logging)
            self.websocket.send(message)
            
        if self.ws_thread.is_alive():
            if '{"session":' in message:
                self.__print_and_log_ws_message(recv=False, msg=message, logging=self.logging)
                self.websocket.send(message)
            else:
                threading.Thread(target=__thread_send, args=[message]).start()
            return True
        else:
            print("***Error: Websocket does not exist.")
            return False
        
    def close_websocket(self) -> bool:
        self.websocket.close(status=1000)

    def __run_websocket(self, verbose: bool = False,) -> dict | str:
        ws_url = f"wss://{self.domain}/{self.env}/ws?oauth_token={self.access_token}"
        cookie_arg = {"cookie": f"api={self.session_cookie}"} if self.session_cookie else {}
        user_agent = {"User-Agent": self.user_agent}
        self.__print_and_log_request(
            req=(ws_url, dict(**cookie_arg, **user_agent)), 
            verbose=verbose, 
            logging=self.logging,
        )
        self.websocket = websocket.WebSocketApp(
            url=ws_url,
            on_error=self.__ws_on_error,
            on_close=self.__ws_on_close,
            on_message=self.__ws_on_message, 
            header=[f"{k}: {v}" for k, v in user_agent.items()],
            **cookie_arg,
            )
        self.__print_and_log_response(
            resp=self.websocket.has_errored, 
            verbose=verbose, 
            logging=self.logging,
        )
        self.websocket.on_open = self.__ws_on_open
        self.websocket.run_forever()
    
    def __ws_on_open(self, websocket):
        print("***Websocket open.")

    def __ws_on_error(self, websocket, error):
        # print(f"Error: {error}")
        pass

    def __ws_on_close(self, websocket, close_status_code, close_msg):
        self.ws_open_flag.clear()
        self.websocket = None
        print("***Websocket closed.")

    def __ws_on_message(self, websocket, message):
        str_msg = message.decode('utf-8')
        self.__print_and_log_ws_message(recv=True, msg=str_msg, logging=self.logging)
        if '"sts"' in str_msg: # previously used 'system' message as flag for ready ws, but this is too early
            self.ws_open_flag.set()
        try:
            json_msg = json.loads(str_msg)
            if json_msg['message'] == 'waiting for session':
                self.get_session_cookie()
                # self.send_websocket(message=f"{{\"session\":\"12345\"}}")
                self.send_websocket(message=f"{{\"session\":\"{self.session_cookie}\"}}")
            if self.ws_msg_method:
                self.ws_msg_method(json_msg)
        except json.JSONDecodeError:
            print(f"***Decode error: {message}")
            
    def get_session_cookie(self, verbose: bool = False) -> str:
        self.session_cookie = self.request("POST", "/tickle", verbose=verbose)["body"]["session"]
        self.session_cookie_updated = int(time()*1000)
        print('***Found session: {} retrieved {}'.format(
            self.session_cookie,
            ctime(self.session_cookie_updated/1000),
        ))
        self.__write_session_cache()
        return self.session_cookie
    
    def __print_and_log_request(
            self, 
            req: requests.PreparedRequest | tuple, 
            verbose: bool, 
            logging: bool,
    ) -> None:
        tstamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(req, tuple):
            rqm, rqu, rqh, rqb = 'GET', req[0], req[1], ''
        else:
            rqm, rqu, rqh = req.method, req.url, req.headers
            rqb = f"\n{pprint.pformat(json.loads(req.body))}\n" if req.body else ""
        rqh_fmt = '\n'.join(f"{k}: {v}" for k, v in rqh.items()).replace(', ', ',\n    ')
        short_str = f"{tstamp} REQUEST{58*'-'}\n{rqm} {unquote(rqu)}"
        long_str = f"{short_str}\n{rqh_fmt}\n{rqb}"
        if logging:
            with self.log_path.open('a') as f:
                f.write(long_str)
        print(long_str) if verbose else print(short_str)
            
    def __print_and_log_response(
            self, 
            resp: requests.Response | bool, 
            verbose: bool, 
            logging: bool,
    ) -> None:
        tstamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(resp, bool):
            rsc, rsr = 'Has errored:', str(resp)
            rtt = rsh = rsb = ''
        else:
            rsc, rsr = resp.status_code, resp.reason
            rsh_to_show = self.headers_to_print(set(resp.headers.keys()))
            rsh = '\n'.join([f"{k}: {v}" for k, v in resp.headers.items() if k in rsh_to_show])
            rtt = f"elapsed={round(resp.elapsed.total_seconds()*1000, 3)}\n"
            try:
                rsb = f"\n{pprint.pformat(resp.json())}\n" if resp.text else ""
            except json.JSONDecodeError:
                rsb = resp.text
        short_str = f"{rsc} {rsr}\n"
        long_str = f"{tstamp} RESPONSE {rtt}{short_str}{rsh}\n{rsb}\n"
        if logging:
            with self.log_path.open('a') as f:
                f.write(long_str)
        print(long_str) if verbose else print(short_str)
        
    def __print_and_log_ws_message(
            self, 
            recv: bool,
            msg: str,
            logging: bool,
    ) -> None:
        tstamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if recv:
            recv_str = f"{tstamp} -> WS RECV"
            try:
                json_msg = json.loads(msg)
                short_str = f"{recv_str} {json_msg['topic']}\n"
                long_str = f"{recv_str} {json_msg['topic']} {msg}\n"
            except:
                short_str = long_str = f"{recv_str} {msg}\n"
        else:
            short_str = long_str = f"\n{tstamp} <- WS SEND {msg}\n"
        if logging:
            with self.log_path.open('a') as f:
                f.write(long_str)
        print(long_str) if self.verbose else print(short_str)