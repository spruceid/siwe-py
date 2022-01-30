DOMAIN = "(?P<domain>([^?#]*)) wants you to sign in with your Ethereum account:"
ADDRESS = "\\n(?P<address>0x[a-zA-Z0-9]{40})\\n\\n"
STATEMENT = "((?P<statement>[^\\n]+)\\n)?"
URI = "(([^:?#]+):)?(([^?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))"
URI_LINE = f"\\nURI: (?P<uri>{URI}?)"
VERSION = "\\nVersion: (?P<version>1)"
CHAIN_ID = "\\nChain ID: (?P<chainId>[0-9]+)"
NONCE = "\\nNonce: (?P<nonce>[a-zA-Z0-9]{8,})"
DATETIME = "([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))"
ISSUED_AT = f"\\nIssued At: (?P<issuedAt>{DATETIME})"
EXPIRATION_TIME = f"(\\nExpiration Time: (?P<expirationTime>{DATETIME}))?"
NOT_BEFORE = f"(\\nNot Before: (?P<notBefore>{DATETIME}))?"
REQUEST_ID = "(\\nRequest ID: (?P<requestId>[-._~!$&'()*+,;=:@%a-zA-Z0-9]*))?"
RESOURCES = f"(\\nResources:(?P<resources>(\\n- {URI}?)+))?"
REGEX_MESSAGE = f"^{DOMAIN}{ADDRESS}{STATEMENT}{URI_LINE}{VERSION}{CHAIN_ID}{NONCE}{ISSUED_AT}{EXPIRATION_TIME}{NOT_BEFORE}{REQUEST_ID}{RESOURCES}$"
ERC1271_ABI = [
    {
        {
            "constant": False,
            "inputs": [
                {"name": "_hash", "type": "bytes32"},
                {"name": "_signature", "type": "bytes memory"},
            ],
            "name": "isValidSignature",
            "outputs": [{"name": "magicValue", "type": "bytes4"}],
            "payable": False,
            "type": "function",
        }
    }
]
ERC1271_MAGIC_VALUE = 0x1626BA7E
