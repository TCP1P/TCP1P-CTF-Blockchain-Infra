import os
import re
import shlex
import sys
import json
import time
import random
import signal
import asyncio
import subprocess
from threading import Thread
from typing import Callable, Literal
from uuid import uuid4

# Third-party imports
from base58 import b58encode
from web3 import Web3
from eth_account import Account as EthAccount
from eth_account.hdaccount import generate_mnemonic
from solders.keypair import Keypair # type: ignore
from starknet_py.contract import Contract as CairoContract
from starknet_py.net.account.account import Account as CairoAccount, KeyPair as CairoKeyPair
from starknet_py.net.full_node_client import FullNodeClient as CairoFullNodeClient
from solana.rpc.async_api import AsyncClient as SolanaClient

from sandbox.helper import FileLock, PersistentStore
from .solana_helper import is_solved as solana_is_solved

EthAccount.enable_unaudited_hdwallet_features()

# Local imports
from .type import AccountInfo, NodeInfo

# Environment configuration
BLOCKCHAIN_TYPE = os.getenv("BLOCKCHAIN_TYPE")
print("Starting Blockchain manager...")
if not BLOCKCHAIN_TYPE:
    print("BLOCKCHAIN_TYPE environment variable not defined")
    sys.exit(1)

# Directory setup
INSTANCE_BY_TEAM_DIR = "/tmp/instances-by-team"
INSTANCE_BY_UUID_DIR = "/tmp/instances-by-uuid"
PICKLE_STATE_FILE = "/tmp/solana_state.pickle"
LOCK_FILE = "/tmp/solana.lock"
os.makedirs(INSTANCE_BY_TEAM_DIR, exist_ok=True)
os.makedirs(INSTANCE_BY_UUID_DIR, exist_ok=True)

EVM_VERSION = os.getenv("EVM_VERSION") or "latest"
ANVIL_EXTRA_OPTIONS = shlex.split(os.getenv("ANVIL_EXTRA_OPTIONS") or "")

if BLOCKCHAIN_TYPE == "eth":
    print("EVM_VERSION:", EVM_VERSION)

def get_solana_state():
    store = PersistentStore(PICKLE_STATE_FILE)
    state = store.get('solana_state')
    if state:
        return state['validator_pid'], state['system_keypair']
    return None, None

def save_solana_state(pid, keypair):
    store = PersistentStore(PICKLE_STATE_FILE)
    store.set('solana_state', {
        'validator_pid': pid,
        'system_keypair': keypair
    })

async def initialize_solana_validator():
    global VALIDATOR_PROCESS_ID, SYSTEM_KEYPAIR
    
    with FileLock(LOCK_FILE):
        # Check if another process has already initialized
        pid, keypair = get_solana_state()
        if pid is not None:
            VALIDATOR_PROCESS_ID = pid
            SYSTEM_KEYPAIR = keypair
            return

        # Initialize new validator
        VALIDATOR_PROCESS_ID = None
        SYSTEM_KEYPAIR = Keypair()
        
        node_port = 3001
        node_uuid = str(uuid4())
        
        print("Starting Solana validator...")
        VALIDATOR_PROCESS_ID = (await asyncio.create_subprocess_exec(
            "solana-test-validator", "--rpc-port", str(node_port), "--ledger", node_uuid,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )).pid
        
        # Save state immediately after getting PID
        save_solana_state(VALIDATOR_PROCESS_ID, SYSTEM_KEYPAIR)

        # Wait for validator to be ready
        while True:
            try:
                subprocess.run(
                    ["solana", "cluster-version", "--url", f"http://0.0.0.0:{node_port}"],
                    check=True,
                    capture_output=True,
                    timeout=5
                )
                print("Solana validator is ready!")
                break
            except subprocess.TimeoutExpired:
                continue
            except subprocess.CalledProcessError:
                await asyncio.sleep(0.5)

# Initialize Solana validator if using Solana
if BLOCKCHAIN_TYPE == "solana":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(initialize_solana_validator())

if BLOCKCHAIN_TYPE != "solana":
    VALIDATOR_PROCESS_ID = None
    SYSTEM_KEYPAIR = None

# Helper functions
def instance_exists(uuid: str) -> bool:
    return os.path.exists(f"{INSTANCE_BY_UUID_DIR}/{uuid}")

def team_instance_exists(team_id: str) -> bool:
    return os.path.exists(f"{INSTANCE_BY_TEAM_DIR}/{team_id}")

def load_instance(uuid: str) -> NodeInfo:
    with open(f"{INSTANCE_BY_UUID_DIR}/{uuid}", "r") as file:
        return NodeInfo(**json.load(file))

def load_team_instance(team_id: str) -> NodeInfo:
    with open(f"{INSTANCE_BY_TEAM_DIR}/{team_id}", "r") as file:
        return NodeInfo(**json.load(file))

def remove_instance_data(node_info: NodeInfo):
    os.remove(f"{INSTANCE_BY_UUID_DIR}/{node_info.uuid}")
    os.remove(f"{INSTANCE_BY_TEAM_DIR}/{node_info.team}")

def save_instance_data(node_info: NodeInfo):
    with open(f"{INSTANCE_BY_UUID_DIR}/{node_info.uuid}", "w") as file:
        json.dump(node_info.to_dict(), file)
    with open(f"{INSTANCE_BY_TEAM_DIR}/{node_info.team}", "w") as file:
        json.dump(node_info.to_dict(), file)

# Node management functions
def terminate_node_process(node_info: NodeInfo):
    print(f"Terminating node {node_info.team} {node_info.uuid}")
    remove_instance_data(node_info)
    if BLOCKCHAIN_TYPE != "solana":
        os.kill(node_info.pid, signal.SIGTERM)

def schedule_node_termination(node_info: NodeInfo):
    def termination_task():
        time.sleep(1800)  # 30 minutes
        if instance_exists(node_info.uuid):
            terminate_node_process(node_info)
    
    termination_thread = Thread(target=termination_task)
    termination_thread.start()
    return termination_thread

# Blockchain-specific node launchers
async def launch_cairo_node(team_id: str) -> NodeInfo | None:
    if not team_id:
        return None

    node_port = random.randint(30000, 60000)
    node_uuid = str(uuid4())
    seed_message = "Seed to replicate this account sequence: "
    account_pattern = re.compile(
        r"Account address.*?(0x[a-f0-9]+).*?Private key.*?(0x[a-f0-9]+).*?Public key.*?(0x[a-f0-9]+)",
        flags=re.DOTALL
    )

    # Start Starknet devnet process
    devnet_process = await asyncio.create_subprocess_exec(
        "starknet-devnet",
        f"--port={node_port}",
        "--accounts=2",
        stdout=asyncio.subprocess.PIPE,
    )

    # Wait for node initialization
    client = CairoFullNodeClient(f"http://127.0.0.1:{node_port}")
    output = await devnet_process.stdout.readline()
    while seed_message.encode() not in output:
        output += b"\n" + await devnet_process.stdout.readline()

    # Verify node readiness
    while True:
        try:
            await client.get_block()
            break
        except Exception:
            await asyncio.sleep(0.1)

    # Extract account information
    account_matches = account_pattern.findall(output.decode())
    node_accounts = [
        AccountInfo(
            address=match[0],
            private_key=match[1],
            public_key=match[2]
        ) for match in account_matches
    ]

    # Create node information
    seed_match = re.search(f"{seed_message}(.*)$", output.decode())
    node_info = NodeInfo(
        port=node_port,
        accounts=node_accounts,
        pid=devnet_process.pid,
        uuid=node_uuid,
        team=team_id,
        seed=seed_match.group(1) if seed_match else None
    )

    schedule_node_termination(node_info)
    return node_info

def launch_ethereum_node(team_id: str) -> NodeInfo:
    node_port = random.randint(30000, 60000)
    mnemonic = generate_mnemonic(12, "english")
    node_uuid = str(uuid4())

    
    # Start Anvil process
    anvil_process = subprocess.Popen(
        args=[
            "anvil",
            "--accounts", "2",
            "--balance", "5000",
            "--mnemonic", mnemonic,
            "--port", str(node_port),
            "--block-base-fee-per-gas", "0",
            "--hardfork", EVM_VERSION,
            *ANVIL_EXTRA_OPTIONS
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Wait for node initialization
    web3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{node_port}"))
    while True:
        if anvil_process.poll() is not None:
            raise RuntimeError("Anvil process failed to start")
        if web3.is_connected():
            break
        time.sleep(0.1)

    # Generate accounts
    deployer_account = EthAccount.from_mnemonic(mnemonic, account_path="m/44'/60'/0'/0/0")
    player_account = EthAccount.from_mnemonic(mnemonic, account_path="m/44'/60'/0'/0/1")

    node_accounts = [
        AccountInfo(
            address=deployer_account.address,
            private_key=deployer_account.key.hex(),
            public_key=deployer_account.address
        ),
        AccountInfo(
            address=player_account.address,
            private_key=player_account.key.hex(),
            public_key=player_account.address
        )
    ]

    node_info = NodeInfo(
        port=node_port,
        accounts=node_accounts,
        pid=anvil_process.pid,
        uuid=node_uuid,
        team=team_id,
        seed=mnemonic
    )

    schedule_node_termination(node_info)
    return node_info

# for solana we can only deploy one node because it's complicated to setup the faucet port
async def launch_solana_node(team_id: str) -> NodeInfo:
    node_port = 3001
    node_uuid = str(uuid4())

    # Generate keypairs
    system_keypair = SYSTEM_KEYPAIR
    player_keypair = Keypair()
    context_keypair = Keypair()

    node_accounts = [
        AccountInfo(
            address=str(system_keypair.pubkey()),
            private_key=b58encode(bytes(system_keypair)).decode(),
            public_key=str(system_keypair.pubkey())
        ),
        AccountInfo(
            address=str(player_keypair.pubkey()),
            private_key=b58encode(bytes(player_keypair)).decode(),
            public_key=str(player_keypair.pubkey())
        ),
        AccountInfo(
            address=str(context_keypair.pubkey()),
            private_key=b58encode(bytes(context_keypair)).decode(),
            public_key=str(context_keypair.pubkey())
        ),
    ]

    node_info = NodeInfo(
        port=node_port,
        accounts=node_accounts,
        pid=VALIDATOR_PROCESS_ID,
        uuid=node_uuid,
        team=team_id,
        seed=None,
        contract_addr=None
    )

    schedule_node_termination(node_info)
    return node_info

# Main blockchain manager class
class BlockchainManager:
    def __init__(self, blockchain_type: Literal["cairo", "eth", "solana"]):
        self.blockchain_type = blockchain_type
        self.client = self._initialize_client()

    def _initialize_client(self):
        if self.blockchain_type == "cairo":
            return CairoFullNodeClient("http://127.0.0.1:8545")
        elif self.blockchain_type == "eth":
            return Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        return None

    async def start_instance(
        self,
        team_id: str,
        deploy_handler: Callable[
            [CairoFullNodeClient, CairoAccount, CairoAccount], str
        ] | Callable[[Web3, str, str, str], str]
        | Callable[[SolanaClient, Keypair, Keypair, Keypair], str]
    ) -> NodeInfo:
        if team_instance_exists(team_id):
            raise RuntimeError("Instance already exists for this team")

        node_info = None
        if self.blockchain_type == "cairo":
            node_info = await self._start_cairo_instance(team_id, deploy_handler)
        elif self.blockchain_type == "eth":
            node_info = await self._start_ethereum_instance(team_id, deploy_handler)
        elif self.blockchain_type == "solana":
            node_info = await self._start_solana_instance(team_id, deploy_handler)

        if not node_info:
            raise RuntimeError("Failed to create blockchain instance")
        
        save_instance_data(node_info)
        return node_info

    async def _start_cairo_instance(self, team_id: str, deploy_handler):
        node_info = await launch_cairo_node(team_id)
        if not node_info:
            return None

        client = CairoFullNodeClient(f"http://127.0.0.1:{node_info.port}")
        system_account = await self._create_cairo_account(client, node_info.accounts[1])
        player_account = await self._create_cairo_account(client, node_info.accounts[0])
        
        contract_address = hex(await deploy_handler(client, system_account, player_account))
        node_info.contract_addr = contract_address
        return node_info

    async def _create_cairo_account(self, client, account_info):
        return CairoAccount(
            client=client,
            address=account_info.address,
            key_pair=CairoKeyPair.from_private_key(account_info.private_key),
            chain=await client.get_chain_id()
        )

    async def _start_ethereum_instance(self, team_id: str, deploy_handler):
        node_info = launch_ethereum_node(team_id)
        web3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{node_info.port}"))
        
        deployer_account = EthAccount.from_mnemonic(
            node_info.seed, account_path="m/44'/60'/0'/0/0"
        )
        contract_address = deploy_handler(
            web3,
            deployer_account.address,
            deployer_account.key.hex(),
            node_info.accounts[1].address
        )
        if asyncio.iscoroutine(deploy_handler):
            contract_address = await contract_address
        
        node_info.contract_addr = contract_address
        return node_info

    async def _start_solana_instance(self, team_id: str, deploy_handler):
        node_info = await launch_solana_node(team_id)
        client = SolanaClient(f"http://0.0.0.0:{node_info.port}")
        
        system_keypair = Keypair.from_base58_string(node_info.accounts[0].private_key)
        player_keypair = Keypair.from_base58_string(node_info.accounts[1].private_key)
        context_keypair = Keypair.from_base58_string(node_info.accounts[2].private_key)
        
        contract_address = await deploy_handler(client, system_keypair, player_keypair, context_keypair)
        node_info.contract_addr = contract_address
        return node_info

    def terminate_instance(self, team_id: str):
        if not team_instance_exists(team_id):
            raise RuntimeError("No instance exists for this team")
        terminate_node_process(load_team_instance(team_id))

    async def verify_solution(self, team_id: str) -> bool:
        if not team_instance_exists(team_id):
            raise RuntimeError("Instance not found for this team")

        node_info = load_team_instance(team_id)
        if self.blockchain_type == "cairo":
            return await self._check_cairo_solution(node_info)
        elif self.blockchain_type == "eth":
            return self._check_ethereum_solution(node_info)
        elif self.blockchain_type == "solana":
            return await self._check_solana_solution(node_info)
        return False

    async def _check_cairo_solution(self, node_info: NodeInfo) -> bool:
        client = CairoFullNodeClient(f"http://127.0.0.1:{node_info.port}")
        system_account = await self._create_cairo_account(client, node_info.accounts[1])
        
        contract = await CairoContract.from_address(
            int(node_info.contract_addr, 16), system_account
        )
        result = await contract.functions.get("is_solved").call()
        return result[0] if isinstance(result, (tuple, list)) else result

    def _check_ethereum_solution(self, node_info: NodeInfo) -> bool:
        web3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{node_info.port}"))
        call_data = web3.eth.call({
            "to": node_info.contract_addr,
            "data": Web3.keccak(text="isSolved()")[:4],
        })
        return int(call_data.hex(), 16) == 1

    async def _check_solana_solution(self, node_info: NodeInfo) -> bool:
        client = SolanaClient(f"http://0.0.0.0:{node_info.port}")
        system_keypair = Keypair.from_base58_string(node_info.accounts[0].private_key)
        context_keypair = Keypair.from_base58_string(node_info.accounts[2].private_key)
        # program_id = Pubkey(node_info.contract_addr)
        is_solved = await solana_is_solved(client, system_keypair, context_keypair)
        return is_solved

# Global instance initialization
BLOCKCHAIN_MANAGER = BlockchainManager(BLOCKCHAIN_TYPE)
