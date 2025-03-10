from dataclasses import dataclass, field, asdict
from typing import List, Optional

@dataclass
class AccountInfo:
    address: str
    private_key: str
    public_key: str

@dataclass
class NodeInfo:
    port: str
    accounts: List[AccountInfo]
    pid: int
    uuid: str
    team: str
    seed: str
    contract_addr: Optional[str] = None

    def __post_init__(self):
        # Convert dicts to AccountInfo instances
        if isinstance(self.accounts, list):
            self.accounts = [AccountInfo(**acc) if isinstance(acc, dict) else acc for acc in self.accounts]

    def to_dict(self):
        return asdict(self)