from abnf.parser import Rule as _Rule
from abnf.grammars.misc import load_grammar_rules


@load_grammar_rules()
class Rule(_Rule):
    """Rules from RFC 5234"""

    grammar = [
        "ALPHA          =  %x41-5A / %x61-7A   ; A-Z / a-z",
        "LF             =  %x0A \
        ; linefeed",
        "DIGIT          =  %x30-39 \
        ; 0-9",
        'HEXDIG         =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"',
    ]
