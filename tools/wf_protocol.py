"""Prespecified round and arm order shared by collection and analysis."""

ROUND_SEEDS = (1475067252, 929854378, 1997314573, 3200583649, 1259733358, 1713829992)
ORDERS = (
    ("relay30", "relay5", "undefended"),
    ("relay30", "undefended", "relay5"),
    ("relay5", "undefended", "relay30"),
    ("relay5", "relay30", "undefended"),
    ("undefended", "relay30", "relay5"),
    ("undefended", "relay5", "relay30"),
)
