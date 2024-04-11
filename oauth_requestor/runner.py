from webapi_session import WebAPIConsumer
from import_consumer import get_id_and_session_args
from webapi_orders import *
import time
import json


your_consumer_key, user_identifier = "TESTCONS", "msull3647"

def main():
    s = WebAPIConsumer(
        init_brokerage=True,
        verbose=True,
        env='v1/api',
        # print_all_headers=True,
        **get_id_and_session_args(consumer=your_consumer_key, user=user_identifier),
    )

    # s.request(POST, '/logout')

    acct = s.request(GET, "/portfolio/accounts", verbose=True)["body"][0]["id"]

    # s.request(GET, '/iserver/auth/status')
    # s.request(POST, '/iserver/auth/ssodh/init', body={'compete': True, 'publish': True})

    s.request(GET, '/iserver/auth/status')
    # accts = [a['id'] for a in s.request(GET, "/portfolio/subaccounts", verbos: e=True)["body"]]
    # acct, subaccts = accts[0], accts[1:]

    s.request(GET, '/iserver/accounts', verbose=True)

    s.request(GET, '/portfolio2/accounts')

    # s.open_websocket(get_cookie=True, verbose=False)

    # s.send_websocket("sor+{}")
    # s.send_websocket("str+{\"days\":1}")

    # submit_order(s, acct, [aapl])

    # s.request(GET, f"/portfolio/{acct}/positions")

    # s.request(GET, f"/portfolio/{acct}/positions/0")

    # r_all = s.request(POST, f"/portfolio/allocation", body={'acctIds': [s for s in subaccts]})['body']

    # r_0 = s.request(POST, f"/portfolio/allocation", body={'acctIds': [subaccts[0]]})['body']

    # r_1 = s.request(POST, f"/portfolio/allocation", body={'acctIds': [subaccts[1]]})['body']

    # print(r_all['assetClass']['long']['CASH'])
    # r_sum = r_0['assetClass']['long']['CASH'] + r_1['assetClass']['long']['CASH']
    # print(r_sum)

    

#     smh = {
#     "exchange":"SMART",
#     "period":"2h",
#     "bar":"5min",
#     "outsideRth":False,
#     "source":"trades",
#     "format":"%h/%l"
# }
    
    # def test_method(json_msg):
    #     if 'smh' in json_msg['topic']:
    #         msg_conid = json_msg['topic'][4:]


    # conids = [
    #     15016138,
    #     # 15016125,
    #     # 114900056,
    #     # 15016128,
    #     # 15016133,
    #     # 39453424,
    #     # 61664938,
    #     # 14433401,
    #     # 208558338,
    #     # 15016234,
    #     # 114900050,
    #     # 15016239,
    #     # 15016241,
    #     # 114900055
    # ]
    
    # fields_str = '{' + '"fields":{"exchange":"IDEALPRO","period":"2h","bar":"5min","outsideRth":false,"source":"midpoint","format":"%h/%l"}' + '}'
    # for conid in conids:
    #     s.send_websocket(f"smh+{conid}+{fields_str}")

    # s.send_websocket('shs+cmb+{{"UCO":"756733","UST":"STK","SMB":"SPY","UEX":"SMART","STY":"OPT","STN":{{"context":{{"selected_strategy":"leg_by_leg"}}')

    # s.send_websocket(f"sbd+{acct}+265598+SMART")

    # s.request(GET, f"/iserver/account/{acct}/summary")


    # s.send_websocket("smd+12087792+{\"fields\":[\"31\",\"84\",\"85\",\"86\",\"88\"]}")
    # s.send_websocket(f"sbd+{acct}+533620665+CME")
    # s.send_websocket(f"sbd+{acct}+12087792+IDEALPRO")
    
    # s.send_websocket(f"sbd+{acct}+479624278+PAXOS")
    

    # s.request(GET, '/portfolio/{acct}/positions/0')

    # s.request(GET, '/iserver/auth/status')

    # s.request(GET, f"/portfolio2/accounts")

    # s.request(GET, f"/portfolio2/positions")

    # s.request(POST, "/iserver/contract/rules", body={"conid":673601622,"exchange":"OVERNIGHT","isBuy":True,})

    # s.request(POST, "/iserver/contract/rules", body={"conid":265598,"exchange":"IBEOS","isBuy":True,})

    # s.request(GET, "/trsrv/secdef?conids=265598")

    # s.request(POST, "/iserver/questions/suppress", body={"messageIds": [123, 456]})
    # s.request(POST, '/iserver/questions/suppress/reset')

    # s.request(GET, "/ibcust/marketdata/subscriptions")

    # s.request(GET, "/acesws/marketdata/subscriptions")



    

    # s.request(POST, '/iserver/questions/suppress', body={"messageIds": [""]})

    # s.request(POST, f"/iserver/marketdata/snapshot", body={'conids': ["12087792"], 'fields': ["31"]})

    

GET, POST, DELETE, PUT = "get", "post", "delete", "put"
BUY, SELL = "BUY", "SELL"

if __name__ == "__main__":
    main()
