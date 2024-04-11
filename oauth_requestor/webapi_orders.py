from webapi_session import WebAPIConsumer

def submit_order(client: WebAPIConsumer, acct: str, orders: list):
    oid = None
    resp = client.request("post", f"/iserver/account/{acct}/orders", body={"orders": orders})
    resp_body = resp['body']
    while not oid:
        try:
            oid = resp_body[0]['order_id']
        except KeyError:
            try:
                replyid = resp_body[0]['id']
            except KeyError:
                # some other unrecoverable failure
                pass
            else:
                resp = client.request("post", f"/iserver/reply/{replyid}", body={'confirmed': True})
                resp_body = resp['body']
        finally:
            replyid = None
    return oid, resp

def build_order(acct: str, side: str, quantity: int, instrument: dict, handling: dict) -> dict:
    order = {"acctId": acct, "side": side, "quantity": quantity}
    order.update(instrument)
    order.update(handling)
    return order

ltc = {
    "conid": 498989715,
    "secType": "498989715:CRYPTO",
    "conidex": "498989715@PAXOS",
    "orderType": "LMT",
    # "useAdaptive": True,
    "side": "BUY",
    "price": 68.20,
    "tif": "PAX",
    "quantity": 20,
}

aapl = {
    "conid": 265598,
    "secType": "265598:STK"
}

es_dec23_fut = {
    "conid": 495512552,
    "secType":"495512552:FUT"
}

ibm = {
    "conid": 8314,
    "secType":"8314:STK"
}

mkt = {
    "orderType": "MKT",
    "tif": "DAY"
}


aapl = {
    "conid": 14094,
    "secType": "14094:STK",
    "orderType": "MKT",
    # "useAdaptive": True,
    "side": "SELL",
    # "price": 120,
    "tif": "DAY",
    "quantity": 100,
    # "trailingAmt": 3.75,
    # "trailingType": "amt"
}


#    "orderType": "MKT",
    # # "outsideRTH": True,
    # "side": "BUY",
    # "tif": "DAY",
    # # "fxQty": 1000000000000,
    # # "cashQty": 1000000000000,
    # "quantity": 1000,

# aapl = {
#     "acctId": acct,
#     "conid": 265598,
#     "secType": "265598:STK",
#     "orderType": "TRAIL",
#     # "useAdaptive": True,
#     "side": "SELL",
#     "price": 188,
#     "tif": "GTC",
#     "quantity": 100,
#     "trailingAmt": 3.75,
#     "trailingType": "amt"
# }




#     "orderType": "LMT",
#     "price": 4250,
#     # "auxPrice": 10,
#     "side": "BUY",
#     "tif":"GTC",
#     "quantity": 10,
#     # "useAdaptive": True,
#     }


#     "orderType": "LMT",
#     "price": 151,
#     "side": "BUY",
#     "tif":"GTC",
#     "quantity": 100,
#     "useAdaptive": True



        # if isinstance(resp_body, dict):
        #     try:
        #         oid = resp_body['order_id']
        #     except KeyError:
        #         if 'id' in resp_body:
        #             # order requires reply to message to proceed
        #             replyid = resp_body['id']
        #             resp = client.request("post", f"/iserver/reply/{replyid}", body={'confirmed': True})
        #         else:
        #             # some other unrecoverable failure
        #             pass
        #     else:
        #         replyid = None
        # elif isinstance(resp_body, list):
        #     try:
        #         oid = resp_body[0]['order_id']
        #         replyid = None
        #     except KeyError:
        #         if 'id' in resp_body[0]:
        #             # order requires reply to message to proceed
        #             replyid = resp_body[0]['id']
        #             resp = client.request("post", f"/iserver/reply/{replyid}", body={'confirmed': True})
        #         else:
        #             # some other unrecoverable failure
        #             pass
        # if replyid = None