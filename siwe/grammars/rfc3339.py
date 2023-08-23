"""Date ABNF definition."""

from typing import ClassVar, List

from abnf.grammars.misc import load_grammar_rules
from abnf.parser import Rule as _Rule

from . import rfc5234


@load_grammar_rules(
    [
        # RFC 5234
        ("DIGIT", rfc5234.Rule("DIGIT")),
    ]
)
class Rule(_Rule):
    """Rules from RFC 3339."""

    grammar: ClassVar[List] = [
        "date-fullyear = 4DIGIT",
        "date-month = 2DIGIT",
        "date-mday = 2DIGIT",
        "time-hour = 2DIGIT",
        "time-minute = 2DIGIT",
        "time-second = 2DIGIT",
        'time-secfrac = "." 1*DIGIT',
        'time-numoffset = ( "+" / "-" ) time-hour ":" time-minute',
        'time-offset = "Z" / time-numoffset',
        'partial-time = time-hour ":" time-minute ":" time-second [ time-secfrac ]',
        'full-date = date-fullyear "-" date-month "-" date-mday',
        "full-time = partial-time time-offset",
        'date-time = full-date "T" full-time',
    ]
