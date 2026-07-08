from dataclasses import dataclass
from lark import Lark, Transformer, v_args

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
        return PolicyAST(str(name), target, condition[0], condition[1], condition[2], effect)
    def target(self, action_val): return action_val
    def condition(self, expr): return expr
    def expression(self, entity, attr, operator, value): 
        if entity == "provenance": return ("provenance", str(operator), value)
        return (f"{entity}_{attr}", str(operator), value)
    def obligation(self, state_val): return state_val
    def effect(self, effect_val): return str(effect_val)

# --- 2. THE DUAL COMPILER ---
class PacaCompiler:
    def __init__(self):
        self.parser = Lark(alfa_grammar, parser='lalr', transformer=AlfaTreeBuilder())
        
    def compile_to_ast(self, text: str) -> PolicyAST:
        parsed_tree = self.parser.parse(text)
        return parsed_tree.children[0]
        
    def emit_cedar(self, ast: PolicyAST) -> str:
        effect = "forbid" if ast.effect == "deny" else "permit"
        attr = ast.attribute.split('_')[-1]
        
        if ast.attribute == "provenance":
            return f'{effect} (principal, action == Action::"{ast.action}", resource) when {{ context.provenance {ast.operator} "{ast.value}" }};'
        return f'{effect} (principal, action == Action::"{ast.action}", resource) when {{ principal.{attr} {ast.operator} "{ast.value}" }};'

    def emit_asp(self, ast: PolicyAST) -> str:
        head = ast.effect
        if ast.operator == "!=":
            return f'{head} :- action_{ast.action}, not {ast.attribute}(agent, "{ast.value}").'
        return f'{head} :- action_{ast.action}, {ast.attribute}(agent, "{ast.value}").'