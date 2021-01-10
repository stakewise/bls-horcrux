from typing import Any, Dict, NamedTuple

DEPOSIT_CLI_VERSION: str

class BaseChainSetting(NamedTuple):
    ETH2_NETWORK_NAME: str
    GENESIS_FORK_VERSION: bytes

MAINNET: str
WITTI: str
ALTONA: str
MEDALLA: str
SPADINA: str
ZINKEN: str
PYRMONT: str
MainnetSetting: Any
WittiSetting: Any
AltonaSetting: Any
MedallaSetting: Any
SpadinaSetting: Any
ZinkenSetting: Any
PyrmontSetting: Any
ALL_CHAINS: Dict[str, BaseChainSetting]

def get_chain_setting(chain_name: str=...) -> BaseChainSetting: ...
