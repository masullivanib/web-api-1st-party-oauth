from datetime import datetime
from pathlib import Path
import inspect, sys
import json

def get_id_and_session_args(consumer: str, user: str) -> dict:
    pems_path = f"./consumers/{consumer}/{consumer}_pem_paths.json"
    auth_path = f"./consumers/{consumer}/{consumer}-{user}_auth.json"
    sesh_path = f"./consumers/{consumer}/{consumer}-{user}_session.json"
    log_path = f"./logs/{datetime.now().strftime('%Y-%m-%d')}_{consumer}-{user}_log.txt"
    arg_dict = {
        "consumer_key": consumer,
        "session_cache_path": sesh_path,
        "log_path": log_path
        }
    try:
        for k, v in json.loads(Path(pems_path).resolve(True).read_text()).items():
            arg_dict[k] = Path(v).resolve(True).read_bytes()
        arg_dict.update(json.loads(Path(auth_path).resolve(True).read_text()))
        assert all(bool(str(v)) for v in arg_dict.values())
    except (OSError, ValueError) as e:
        print(f"{e}\nExiting...")
        raise SystemExit(0)
    except AssertionError as e:
        print(f"{e}\nEnsure all identity values are nonempty.\nExiting...")
        raise SystemExit(0)
    try:
        arg_dict.update(json.loads(Path(sesh_path).resolve(True).read_text()))
    except FileNotFoundError:
        Path(sesh_path).touch(exist_ok=True)
    Path(log_path).touch(exist_ok=True)
    with Path(log_path).resolve(False).open('a+') as f:
        f.write(f"\n\n{'~'*5} {{}} {{}}\n".format(
            datetime.now().strftime('%H:%M:%S'),
            inspect.getframeinfo(sys._getframe(1)).filename
        ))
    return arg_dict