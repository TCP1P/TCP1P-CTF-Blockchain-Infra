from foundpy import config, Contract

"""
https://github.com/foundry-rs/foundry

- Init new Project: forge init
- testing: forge test -vvv

"""

data = config.from_tcp1p("http://localhost:48334/")

class SetupContract(Contract):
    def __init__(self) -> None:
        super().__init__(
            addr=data['setup_contract'],
            file="./contracts/Setup.sol",
        )
    def is_solved(s):
        result = s.contract.functions.isSolved().call()
        print("is solved:", result)

if __name__ == "__main__":
    setup = SetupContract()
    print(setup.contract.functions.solve().transact())
    setup.is_solved()
    flag = config.flag()
    print("flag:", flag)