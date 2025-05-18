from foundpy import config, Contract

"""
https://github.com/foundry-rs/foundry

- Init new Project: forge init
- testing: forge test -vvv

"""

RPC_URL = "http://localhost:48334/143d5a0b-a1b4-4eda-a1d1-09f33b050a16"
PRIVKEY = "b8105127f7988fb30d1d825ab6922166402827bf1e0d3820962919ad2e90e3ba"
SETUP_CONTRACT_ADDR = "0x4CC316Fc6d998880312188AD6e74B0616aC4376e"
WALLET_ADDR = "0x9B76fFB4e271d61B98263fFD5D8E505E5C621473"

data = config.setup(
    rpc_url=RPC_URL,
    privkey=PRIVKEY,
)

class SetupContract(Contract):
    def __init__(self) -> None:
        super().__init__(
            addr=SETUP_CONTRACT_ADDR,
            file="./contracts/Setup.sol",
        )
    def is_solved(s):
        result = s.contract.functions.isSolved().call()
        print("is solved:", result)

if __name__ == "__main__":
    setup = SetupContract()
    print(setup.contract.functions.solve().transact())
    setup.is_solved()