"""SIWE message parsers."""

import re

import abnf

from .defs import REGEX_MESSAGE
from .grammars import eip4361


class RegExpParsedMessage:
    """Regex parsed SIWE message."""

    def __init__(self, message: str):
        """Parse a SIWE message."""
        expr = re.compile(REGEX_MESSAGE)
        match = re.match(REGEX_MESSAGE, message)

        if not match:
            raise ValueError("Message did not match the regular expression.")

        self.match = match
        self.scheme = match.group(expr.groupindex["scheme"])
        self.domain = match.group(expr.groupindex["domain"])
        self.address = match.group(expr.groupindex["address"])
        self.statement = match.group(expr.groupindex["statement"])
        self.uri = match.group(expr.groupindex["uri"])
        self.version = match.group(expr.groupindex["version"])
        self.nonce = match.group(expr.groupindex["nonce"])
        self.chain_id = match.group(expr.groupindex["chainId"])
        self.issued_at = match.group(expr.groupindex["issuedAt"])
        self.expiration_time = match.group(expr.groupindex["expirationTime"])
        self.not_before = match.group(expr.groupindex["notBefore"])
        self.request_id = match.group(expr.groupindex["requestId"])
        self.resources = match.group(expr.groupindex["resources"])
        if self.resources:
            self.resources = self.resources.split("\n- ")[1:]


class ABNFParsedMessage:
    """ABNF parsed SIWE message."""

    def __init__(self, message: str):
        """Parse a SIWE message."""
        parser = eip4361.Rule("sign-in-with-ethereum")
        try:
            node = parser.parse_all(message)
        except abnf.ParseError as e:
            raise ValueError from e

        for child in node.children:
            if child.name in [
                "scheme",
                "domain",
                "address",
                "statement",
                "uri",
                "version",
                "nonce",
                "chain-id",
                "issued-at",
                "expiration-time",
                "not-before",
                "request-id",
                "resources",
            ]:
                setattr(self, child.name.replace("-", "_"), child.value)

            if child.name == "resources":
                resources = []
                for resource in child.children:
                    resources.extend(
                        [r.value for r in resource.children if r.name == "uri"]
                    )
                self.resources = resources
