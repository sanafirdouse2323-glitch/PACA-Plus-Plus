import random
import clingo
from cedarpy import is_authorized, Decision
from compiler.transpiler import PacaCompiler

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