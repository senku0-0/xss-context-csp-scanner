from .base import Rule, Verdict

class RuleA0(Rule):
    name = "A0_token_reappears"
    
    def evaluate(self, row):
        hit = row["token"] in row["body"]
        return Verdict(hit, "token reappeared" if hit else "token absent")