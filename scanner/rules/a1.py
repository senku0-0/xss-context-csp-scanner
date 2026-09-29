from .base import Rule, Verdict

class RuleA1(Rule):
    name = "A1_payload_verbatim"
    
    def evaluate(self, row):
        hit = row["payload"] in row["body"]
        return Verdict(hit, "payload verbatim" if hit else "payload not verbatim")