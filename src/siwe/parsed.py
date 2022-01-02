import re

from .defs import REGEX_MESSAGE


class ParsedMessage:

    def __init__(self, message: str):
        expr = re.compile(REGEX_MESSAGE)
        match = re.match(REGEX_MESSAGE, message)

        if not match:
            raise Exception("Message did not match the regular expression.");

        self.match = match;
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
