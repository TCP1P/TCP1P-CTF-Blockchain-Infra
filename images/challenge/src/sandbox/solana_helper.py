import os
import re
import asyncio
import tempfile
from pathlib import Path
from typing import Tuple, Dict
import toml, json

from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair  # type: ignore
import re

# Constants
MAX_RETRIES = 20
DELAY = 1
CONTRACTS_DIR = Path("setup")

async def execute_test(test, env: Dict[str, str]):
    env.update(os.environ)
    stdout, stderr = await execute("yarn", "run", "ts-mocha", "-p", "./tsconfig.json", "-t", "1000000", "tests/"+test+".ts", cwd=CONTRACTS_DIR, env=env)
    print("stderr", stderr)
    print("stdout", stdout)
    return extract_message(stdout)

def extract_message(stdout: str) -> str:
    match = re.search(r'{"message":(.*)}', stdout)
    if match:
        return json.loads(match.group(1))
    return ""

async def execute(*args: str, cwd: Path = None, env: Dict[str,str] = os.environ) -> int:
    proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=env
        )
    stdout, stderr = await proc.communicate()
    if proc.returncode == 0:
        return stdout.decode(), None
    return stdout.decode(), stderr.decode()

async def execute_command(*args: str, cwd: Path = None) -> Tuple[str, str]:
    """Execute shell command asynchronously with retries"""
    for _ in range(MAX_RETRIES):
        stdout, stderr = await execute(*args, cwd=cwd)
        if stderr == None:
            return stdout
        await asyncio.sleep(DELAY)
    raise RuntimeError(f"Command failed after {MAX_RETRIES} attempts: {' '.join(args)} {stderr}")



class TempKeyfile:
    """Context manager for temporary keyfile handling.
       Assumes keypair.to_json() returns a JSON string compatible with the Solana CLI."""
    def __init__(self, keypair: Keypair):
        self.keypair = keypair
        self.temp_file = None

    async def __aenter__(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
        self.temp_file.write(str(self.keypair.to_json()))
        self.temp_file.close()
        return Path(self.temp_file.name)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.temp_file:
            os.remove(self.temp_file.name)

async def fund_account(client: AsyncClient, keypair: Keypair, amount: int):
    """Fund account using the Solana CLI airdrop command."""
    await execute_command(
        "solana", "airdrop", str(amount),
        str(keypair.pubkey()),
        "--url", client._provider.endpoint_uri,
        "--commitment", "finalized"
    )

def get_program_id_from_anchor_toml(contracts_dir: Path, program_name: str) -> str:
    """Extract program ID from Anchor.toml configuration.
       (This may still be useful to update your configuration after deployment.)"""
    anchor_toml_path = contracts_dir / "Anchor.toml"
    if not anchor_toml_path.exists():
        raise FileNotFoundError(f"Anchor.toml not found at {anchor_toml_path}")
    
    config = toml.load(anchor_toml_path)
    try:
        return config["programs"]["localnet"][program_name]
    except KeyError:
        raise KeyError(
            f"Program {program_name} not found in [programs.localnet] section of Anchor.toml"
        )

async def deploy_program(client: AsyncClient, system_kp: Keypair, program_name: str) -> str:
    """Deploy Solana program using the CLI and return the deployed program ID.
       Assumes the program binary is at contracts/target/deploy/<program_name>.so."""
    async with TempKeyfile(system_kp) as keyfile:
        stdout = await execute_command(
            "anchor", "deploy", "--program-name", program_name,
            "--provider.cluster", client._provider.endpoint_uri,
            "--provider.wallet", str(keyfile),
            "--", "--commitment", "finalized",
            cwd=CONTRACTS_DIR
        )
    if match := re.search(r'Program Id: (\S+)', stdout):
        return match.group(1)
    
    raise RuntimeError("Failed to extract program ID from deployment output")

async def initialize_idl(client: AsyncClient, system_kp: Keypair, idl_path: Path, program_name: str):
    """Initialize IDL using program ID from Anchor.toml"""
    program_id = get_program_id_from_anchor_toml(CONTRACTS_DIR, program_name)
    async with TempKeyfile(system_kp) as keyfile:
        await execute_command(
            "anchor", "idl", "init", program_id,
            "--filepath", str(idl_path),
            "--provider.cluster", client._provider.endpoint_uri,
            "--provider.wallet", str(keyfile),
            cwd=CONTRACTS_DIR
        )

async def is_solved(client: AsyncClient, system_kp: Keypair, ctx_kp: Keypair):
    async with TempKeyfile(system_kp) as keyfile:
        return await execute_test("is_solved", env={
            "solvedAccount": str(ctx_kp.to_bytes_array()),
            "ANCHOR_PROVIDER_URL": client._provider.endpoint_uri,
            "ANCHOR_WALLET": str(keyfile)
        })