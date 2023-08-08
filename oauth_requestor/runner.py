from webapi_session import WebAPISession


GET, POST, DELETE, PUT = "get", "post", "delete", "put"


def main():
    s = WebAPISession(
        config_path='./config',
        init_brokerage=True,
        logging=True,
        verbose=True,
    )

    acct = s.request(GET, "/portfolio/accounts", verbose=True)
    acct = acct[0]['id']
    s.request(POST, '/tickle')
    s.request(GET, "/iserver/accounts")


if __name__ == "__main__":
    main()
