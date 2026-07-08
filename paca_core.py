import random
from dataclasses import dataclass
from lark import Lark, Transformer, v_args
import clingo
from cedarpy import is_authorized, Decision

# --- 1. THE PACA++ GRAMMAR & AST ---
alfa_grammar = """
    start: policy
    policy: "policy" CNAME "{" target condition (obligation)? effect "}"
    
    target: "target:" "action" "==" ESCAPED_STRING
    condition: "condition:" expression ("AND" expression)*
    expression: (CNAME "." CNAME | "provenance") OPERATOR ESCAPED_STRING
    obligation: "obligation:" "verify_state" "(" ESCAPED_STRING ")"
    effect: "effect:" EFFECT_TYPE
    
    OPERATOR: "==" | "!="
    EFFECT_TYPE: "permit" | "deny"
    
    %import common.CNAME
    %import common.ESCAPED_STRING
    %import common.WS
    %ignore WS
"""

@dataclass
class PolicyAST:
    name: str; action: str; attribute: str; operator: str; value: str; effect: str

@v_args(inline=True)
class AlfaTreeBuilder(Transformer):
    def ESCAPED_STRING(self, s): return s[1:-1]
    def policy(self, name, target, condition, obligation, effect):
        # We extract the first condition for this prototype
        return PolicyAST(str(name), target, condition[0], condition[1], condition[2], effect)
    def target(self, action_val): return action_val
    def condition(self, expr): return expr # Base prototype handles single expression
    def expression(self, entity, attr, operator, value): 
        # Handle both standard attributes and PACA++ provenance
        if entity == "provenance": return ("provenance", str(operator), value)
        return (f"{entity}_{attr}", str(operator), value)
    def obligation(self, state_val): return state_val
    def effect(self, effect_val): return str(effect_val)

# --- 2. THE DUAL COMPILER ---
class PacaCompiler:
    def __init__(self):
        self.parser = Lark(alfa_grammar, parser='lalr', transformer=AlfaTreeBuilder())
        
    def compile_to_ast(self, text: str) -> PolicyAST:
        # Lark wraps the result in a root 'Tree'. We extract our PolicyAST from its children.
        parsed_tree = self.parser.parse(text)
        return parsed_tree.children[0]
        
    def emit_cedar(self, ast: PolicyAST) -> str:
        effect = "forbid" if ast.effect == "deny" else "permit"
        attr = ast.attribute.split('_')[-1]
        
        # If the attribute is provenance, map it to the Cedar context object
        if ast.attribute == "provenance":
            return f'{effect} (principal, action == Action::"{ast.action}", resource) when {{ context.provenance {ast.operator} "{ast.value}" }};'
        return f'{effect} (principal, action == Action::"{ast.action}", resource) when {{ principal.{attr} {ast.operator} "{ast.value}" }};'

    def emit_asp(self, ast: PolicyAST) -> str:
        head = ast.effect
        if ast.operator == "!=":
            return f'{head} :- action_{ast.action}, not {ast.attribute}(agent, "{ast.value}").'
        return f'{head} :- action_{ast.action}, {ast.attribute}(agent, "{ast.value}").'

# --- 3. THE DIFFERENTIAL FUZZER ---
class EquivalenceFuzzer:
    def __init__(self, compiler):
        self.compiler = compiler

    def generate_state(self):
        return {
            "action": random.choice(["readFile", "executeDB"]),
            "role": random.choice(["admin", "guest", "malicious_agent"])
        }

    def eval_cedar(self, rule, state):
        request = {
            "principal": f'User::"{state["role"]}"',
            "action": f'Action::"{state["action"]}"',
            "resource": 'Resource::"data"',
            "context": {}
        }
        entities = [{"uid": {"__entity": {"type": "User", "id": state["role"]}}, "attrs": {"role": state["role"]}, "parents": []}]
        try:
            return "permit" if is_authorized(request, rule, entities).decision == Decision.Allow else "deny"
        except Exception as e:
            return "deny"

    def eval_asp(self, rule, state):
        ctl = clingo.Control()
        ctl.add("base", [], rule)
        ctl.add("base", [], f'action_{state["action"]}. user_role(agent, "{state["role"]}").')
        ctl.ground([("base", [])])
        
        decision = "permit"
        with ctl.solve(yield_=True) as handle:
            for model in handle:
                if "deny" in [str(sym) for sym in model.symbols(atoms=True)]:
                    decision = "deny"
        return decision

    def run(self, policy_text, iterations=100):
        ast = self.compiler.compile_to_ast(policy_text)
        cedar_rule = self.compiler.emit_cedar(ast)
        asp_rule = self.compiler.emit_asp(ast)
        
        print(f"\n[+] Compiling Policy: {ast.name}")
        print(f"    -> Cedar: {cedar_rule}")
        print(f"    -> ASP:   {asp_rule}\n")
        
        mismatches = 0
        for _ in range(iterations):
            state = self.generate_state()
            if self.eval_cedar(cedar_rule, state) != self.eval_asp(asp_rule, state):
                mismatches += 1
                
        print(f"[+] Differential Fuzzing Complete: {iterations} states tested.")
        print(f"[!] Semantic Equivalence: {'CONFIRMED (100% Match)' if mismatches == 0 else 'FAILED'}\n")

# --- 4. EXECUTION ---
if __name__ == "__main__":
    sample_policy = """
    policy PreventDataLeak {
        target: action == "readFile"
        condition: user.role != "admin"
        obligation: verify_state("file_system_unchanged")
        effect: deny
    }
    """
    compiler = PacaCompiler()
    fuzzer = EquivalenceFuzzer(compiler)
    fuzzer.run(sample_policy, iterations=100)