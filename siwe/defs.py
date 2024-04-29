"""Regexes for the various fields."""

SCHEME = "((?P<scheme>([a-zA-Z][a-zA-Z0-9\\+\\-\\.]*))://)?"
DOMAIN = "(?P<domain>([^/?#]+)) wants you to sign in with your Ethereum account:\\n"
ADDRESS = "(?P<address>0x[a-zA-Z0-9]{40})\\n\\n"
STATEMENT = "((?P<statement>[^\\n]+)\\n)?\\n"
URI = "(([^ :/?#]+):)?(//([^ /?#]*))?([^ ?#]*)(\\?([^ #]*))?(#(.*))?"
URI_LINE = f"URI: (?P<uri>{URI}?)\\n"
VERSION = "Version: (?P<version>1)\\n"
CHAIN_ID = "Chain ID: (?P<chainId>[0-9]+)\\n"
NONCE = "Nonce: (?P<nonce>[a-zA-Z0-9]{8,})\\n"
DATETIME = (
    "([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]"
    "([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(.[0-9]+)?"
    "(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))"
)
ISSUED_AT = f"Issued At: (?P<issuedAt>{DATETIME})"
EXPIRATION_TIME = f"(\\nExpiration Time: (?P<expirationTime>{DATETIME}))?"
NOT_BEFORE = f"(\\nNot Before: (?P<notBefore>{DATETIME}))?"
REQUEST_ID = "(\\nRequest ID: (?P<requestId>[-._~!$&'()*+,;=:@%a-zA-Z0-9]*))?"
RESOURCES = f"(\\nResources:(?P<resources>(\\n- {URI})+))?"
REGEX_MESSAGE = (
    f"^{SCHEME}{DOMAIN}{ADDRESS}{STATEMENT}{URI_LINE}{VERSION}{CHAIN_ID}{NONCE}"
    f"{ISSUED_AT}{EXPIRATION_TIME}{NOT_BEFORE}{REQUEST_ID}{RESOURCES}$"
)
