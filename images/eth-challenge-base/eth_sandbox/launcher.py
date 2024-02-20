import hashlib
import json
import os
import string
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

import requests
from eth_account import Account
from web3 import Web3
from web3.exceptions import TransactionNotFound
from web3.types import TxReceipt
from flask import Flask, jsonify, request

HTTP_PORT = os.getenv("HTTP_PORT", "8545")
LAUNCHER_PORT = os.getenv("LAUNCHER_PORT", "8546")
PROXY_PORT = os.getenv("PROXY_PORT", "8547")

CHALLENGE_ID = os.getenv("CHALLENGE_ID", "challenge")
ENV = os.getenv("ENV", "dev")
FLAG = os.getenv("FLAG", "PCTF{placeholder}")

Account.enable_unaudited_hdwallet_features()

@dataclass
class Ticket:
    challenge_id: string
    team_id: string


def check_ticket(ticket: str) -> Ticket:
    if not ticket:
        raise Exception("you haven't provided a ticket yet!")
    if os.environ.get("ALLOW_RANDOM_TICKET"):
        return Ticket(challenge_id=CHALLENGE_ID, team_id=ticket)
    if len(ticket) > 100 or len(ticket) < 8:
        raise Exception('the ticket must be more than 8 characters and less than 100 characters in length.')
    if not all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' for c in ticket):
        raise Exception('ticket must be alphanumeric')
    m = hashlib.sha256()
    m.update(ticket.encode('ascii'))
    digest1 = m.digest()
    m = hashlib.sha256()
    m.update(digest1 + ticket.encode('ascii'))
    if not m.hexdigest().startswith('0000000'):
        raise Exception('PoW: sha256(sha256(ticket) + ticket) must start with 0000000 (digest was ' + m.hexdigest() + ')')
    return Ticket(challenge_id=CHALLENGE_ID, team_id=ticket)


@dataclass
class Action:
    name: str
    handler: Callable[[], int]


def sendTransaction(web3: Web3, tx: Dict) -> Optional[TxReceipt]:
    if "gas" not in tx:
        tx["gas"] = 10_000_000

    if "gasPrice" not in tx:
        tx["gasPrice"] = 0

    # web3.provider.make_request("anvil_impersonateAccount", [tx["from"]])
    txhash = web3.eth.sendTransaction(tx)
    # web3.provider.make_request("anvil_stopImpersonatingAccount", [tx["from"]])

    while True:
        try:
            rcpt = web3.eth.getTransactionReceipt(txhash)
            break
        except TransactionNotFound:
            time.sleep(0.1)

    if rcpt.status != 1:
        raise Exception("failed to send transaction")
    return rcpt


def new_launch_instance_action(
    do_deploy: Callable[[Web3, str], str],
):
    def action():
        ticket = request.args.get("ticket")
        ticket = check_ticket(ticket)
        if not ticket:
            raise Exception("invalid ticket!")

        if ticket.challenge_id != CHALLENGE_ID:
            raise Exception("invalid ticket!")

        data = requests.post(
            f"http://127.0.0.1:{HTTP_PORT}/instance/new",
            headers={
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "team_id": ticket.team_id,
                }
            ),
        ).json()

        if data["ok"] == False:
            raise Exception(data["message"])

        uuid = data["uuid"]
        mnemonic = data["mnemonic"]

        deployer_acct = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/0")
        player_acct = Account.from_mnemonic(mnemonic, account_path=f"m/44'/60'/0'/0/1")

        web3 = Web3(Web3.HTTPProvider(
            f"http://127.0.0.1:{HTTP_PORT}/{uuid}",
            request_kwargs={
                "headers": {
                    "Content-Type": "application/json",
                },
            },
        ))

        setup_addr = do_deploy(web3, deployer_acct.address, player_acct.address)

        with open(f"/tmp/{ticket.team_id}", "w") as f:
            f.write(
                json.dumps(
                    {
                        "uuid": uuid,
                        "mnemonic": mnemonic,
                        "address": setup_addr,
                    }
                )
            )
        return {
            '0': {"UUID":uuid},
            '1': {"RPC Endpoint": "{ORIGIN}/"+uuid},
            '2': {"Private Key": player_acct.privateKey.hex()},
            '3': {"Setup Contract": setup_addr},
            '4': {"Wallet": player_acct._address},
            "message": "your private blockchain has been deployed, it will automatically terminate in 30 minutes"
        }
    return action


def new_kill_instance_action():
    ticket = request.args.get("ticket")
    ticket = check_ticket(ticket)
    if not ticket:
        raise Exception("invalid ticket!")

    if ticket.challenge_id != CHALLENGE_ID:
        raise Exception("invalid ticket!")

    data = requests.post(
        f"http://127.0.0.1:{HTTP_PORT}/instance/kill",
        headers={
            "Content-Type": "application/json",
        },
        data=json.dumps(
            {
                "team_id": ticket.team_id,
            }
        ),
    ).json()

    return {'message':data["message"]}

def is_solved_checker(web3: Web3, addr: str) -> bool:
    result = web3.eth.call(
        {
            "to": addr,
            "data": web3.sha3(text="isSolved()")[:4],
        }
    )
    return int(result.hex(), 16) == 1


def new_get_flag_action():
    ticket = request.args.get("ticket")
    ticket = check_ticket(ticket)
    if not ticket:
        raise Exception("invalid ticket!")
    if ticket.challenge_id != CHALLENGE_ID:
        raise Exception("invalid ticket!")
    try:
        with open(f"/tmp/{ticket.team_id}", "r") as f:
            data = json.loads(f.read())
    except:
        raise Exception("bad ticket")

    web3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{HTTP_PORT}/{data['uuid']}"))

    if not is_solved_checker(web3, data['address']):
        raise Exception("are you sure you solved it?")

    return {"message": FLAG}

def handle_error(e):
    response = jsonify(error=str(e))
    response.status_code = 500
    return response

def run_launcher(do_deploy: Callable[[Web3, str], str]):
    app = Flask(__name__)
    app.get("/flag")(new_get_flag_action)
    app.get("/kill")(new_kill_instance_action)
    app.get("/launch")(new_launch_instance_action(do_deploy))
    app.errorhandler(Exception)(handle_error)
    return app

