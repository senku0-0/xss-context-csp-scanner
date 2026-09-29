from dataclasses import dataclass

@dataclass
class Verdict:
    exploitable: bool
    reason: str

class Rule:
    name = "base"
    def evaluate(self, capture_row: dict) -> Verdict:
        raise NotImplementedError