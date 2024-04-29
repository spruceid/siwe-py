"""Top-level ABNF definition."""

from typing import ClassVar, List

from abnf.grammars import rfc3986
from abnf.grammars.misc import load_grammar_rules
from abnf.parser import Rule as _Rule

from . import rfc3339, rfc5234


@load_grammar_rules(
    [
        # RFC 3986
        ("URI", rfc3986.Rule("URI")),
        ("authority", rfc3986.Rule("authority")),
        ("scheme", rfc3986.Rule("scheme")),
        ("reserved", rfc3986.Rule("reserved")),
        ("unreserved", rfc3986.Rule("unreserved")),
        ("reserved", rfc3986.Rule("reserved")),
        ("pchar", rfc3986.Rule("pchar")),
        # RFC 5234
        ("LF", rfc5234.Rule("LF")),
        ("HEXDIG", rfc5234.Rule("HEXDIG")),
        ("ALPHA", rfc5234.Rule("ALPHA")),
        ("DIGIT", rfc5234.Rule("DIGIT")),
        # RFC 3339
        ("date-time", rfc3339.Rule("date-time")),
    ]
)
class Rule(_Rule):
    """Rules from EIP-4361."""

    grammar: ClassVar[List] = [
        'sign-in-with-ethereum = [ scheme "://" ] domain %s" wants you to sign in with '
        'your Ethereum account:" LF address LF LF [ statement LF ] LF %s"URI: " uri LF '
        '%s"Version: " version LF %s"Chain ID: " chain-id LF %s"Nonce: " nonce LF %s"'
        'Issued At: " issued-at [ LF %s"Expiration Time: " expiration-time ] [ LF %s"'
        'Not Before: " not-before ] [ LF %s"Request ID: " request-id ] [ LF %s"'
        'Resources:" resources ]',
        "domain = authority",
        'address = "0x" 40HEXDIG',
        'statement = 1*( reserved / unreserved / " " )',
        "uri = URI",
        'version = "1"',
        "nonce = 8*( ALPHA / DIGIT )",
        "issued-at = date-time",
        "expiration-time = date-time",
        "not-before = date-time",
        "request-id = *pchar",
        "chain-id = 1*DIGIT",
        "resources = *( LF resource )",
        'resource = "- " URI',
    ]
