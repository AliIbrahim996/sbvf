"""Search algorithms: Random Search, Genetic Algorithm and Cuckoo Search.

They share the interface: search(oracle, budget, seed) -> SearchResult
where budget = maximum number of evaluations (fitness calls), the controlled
resource for a fair comparison.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from .individual import Individual, crossover


@dataclass
class SearchResult:
    algorithm: str
    vuln: str
    confirmed: bool              # was the vulnerability confirmed?
    best_fitness: float
    evals_to_first: int | None   # evaluations until first confirmation (or None)
    total_evals: int
    best_payload: str
    history: list[float] = field(default_factory=list)  # best fitness after each eval


class _Budget:
    """Wraps the oracle to count evaluations, record the convergence curve and
    detect the first confirmation."""

    def __init__(self, oracle, budget: int):
        self.oracle = oracle
        self.budget = budget
        self.used = 0
        self.best = float("-inf")
        self.best_ind = None
        self.confirmed = False
        self.evals_to_first = None
        self.history = []

    def ok(self) -> bool:
        return self.used < self.budget and not self.confirmed

    def assess(self, ind: Individual) -> float:
        fit, confirmed = self.oracle.evaluate(ind)
        ind.fitness = fit
        self.used += 1
        if fit > self.best:
            self.best, self.best_ind = fit, ind.clone()
        if confirmed and self.evals_to_first is None:
            self.evals_to_first = self.used
            self.confirmed = True
        self.history.append(self.best)
        return fit


def _result(name, b: _Budget) -> SearchResult:
    return SearchResult(
        algorithm=name, vuln=b.oracle.vuln, confirmed=b.confirmed,
        best_fitness=b.best, evals_to_first=b.evals_to_first,
        total_evals=b.used,
        best_payload=b.best_ind.render() if b.best_ind else "",
        history=b.history)


# ---------------------------------------------------------------------------
def random_search(oracle, budget: int, seed: int) -> SearchResult:
    rng = random.Random(seed)
    b = _Budget(oracle, budget)
    while b.ok():
        b.assess(Individual.random(oracle.vuln, rng))
    return _result("RS", b)


# ---------------------------------------------------------------------------
def genetic_algorithm(oracle, budget: int, seed: int, *, pop=12, pc=0.8, pm=0.2,
                      tournament=3, elitism=2) -> SearchResult:
    rng = random.Random(seed)
    b = _Budget(oracle, budget)
    population = [Individual.random(oracle.vuln, rng) for _ in range(pop)]
    for ind in population:
        if not b.ok():
            break
        b.assess(ind)

    def select() -> Individual:
        pool = rng.sample(population, min(tournament, len(population)))
        return max(pool, key=lambda i: i.fitness)

    while b.ok():
        population.sort(key=lambda i: i.fitness, reverse=True)
        nxt = [population[i].clone() for i in range(min(elitism, len(population)))]
        while len(nxt) < pop and b.ok():
            p1, p2 = select(), select()
            if rng.random() < pc:
                c1, c2 = crossover(p1, p2, rng)
            else:
                c1, c2 = p1.clone(), p2.clone()
            for c in (c1, c2):
                c.mutate(rng, pm)
                if b.ok():
                    b.assess(c)
                    nxt.append(c)
        population = nxt[:pop]
    return _result("GA", b)


# ---------------------------------------------------------------------------
def _levy_step(rng: random.Random, beta: float = 1.5) -> float:
    """Levy step length via Mantegna's algorithm."""
    sigma = (math.gamma(1 + beta) * math.sin(math.pi * beta / 2) /
             (math.gamma((1 + beta) / 2) * beta * 2 ** ((beta - 1) / 2))) ** (1 / beta)
    u = rng.gauss(0, sigma)
    v = rng.gauss(0, 1)
    return u / (abs(v) ** (1 / beta))


def cuckoo_search(oracle, budget: int, seed: int, *, nests=12, pa=0.25) -> SearchResult:
    rng = random.Random(seed)
    b = _Budget(oracle, budget)
    nests_list = [Individual.random(oracle.vuln, rng) for _ in range(nests)]
    for ind in nests_list:
        if not b.ok():
            break
        b.assess(ind)

    n_genes_max = len(nests_list[0].genome)
    while b.ok():
        # 1) Generate a new cuckoo egg by a Levy flight from a random nest.
        i = rng.randrange(len(nests_list))
        cuckoo = nests_list[i].clone()
        step = abs(_levy_step(rng))
        n_genes = max(1, min(n_genes_max, int(round(step))))  # long steps = exploration
        cuckoo.mutate(rng, pm=0.0, n_genes=n_genes)
        if not b.ok():
            break
        b.assess(cuckoo)
        # 2) Pick a random nest; replace it if the cuckoo is better.
        j = rng.randrange(len(nests_list))
        if cuckoo.fitness > nests_list[j].fitness:
            nests_list[j] = cuckoo
        # 3) Abandon the worst fraction pa of nests.
        nests_list.sort(key=lambda x: x.fitness, reverse=True)
        n_abandon = int(pa * len(nests_list))
        for k in range(len(nests_list) - n_abandon, len(nests_list)):
            if not b.ok():
                break
            nests_list[k] = Individual.random(oracle.vuln, rng)
            b.assess(nests_list[k])
    return _result("CS", b)


ALGORITHMS = {
    "RS": random_search,
    "GA": genetic_algorithm,
    "CS": cuckoo_search,
}
