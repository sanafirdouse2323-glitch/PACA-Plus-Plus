"""Experimental parser and emitters for a deliberately small PACA policy subset.

This module is not a standards-compliant ALFA/UCON+ compiler. In particular,
verify_state obligations are preserved in the AST but rejected by emitters
until a backend can implement their semantics.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from lark import Lark, Transformer, v_args


alfa_grammar = r"""
    start: policy
    policy: "policy" CNAME "{" target condition obligation? effect "}"
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


@dataclass(frozen=True)
class Condition:
    entity: str
    attribute: Optional[str]
    operator: str
    value: str


@dataclass(frozen=True)
class PolicyAST:
    name: str
    action: str
    conditions: tuple[Condition, ...]
    effect: str
    obligation: Optional[str] = None


@v_args(inline=True)
class AlfaTreeBuilder(Transformer):
    def ESCAPED_STRING(self, token):
        return json.loads(str(token))

    def policy(self, name, target, condition, *tail):
        if len(tail) == 2:
            obligation, effect = tail
        elif len(tail) == 1:
            obligation, effect = None, tail[0]
        else:
            raise ValueError("invalid policy structure")
        return PolicyAST(
            name=str(name),
            action=target,
            conditions=condition,
            effect=effect,
            obligation=obligation,
        )

    def target(self, action_value):
        return action_value

    def condition(self, *expressions):
        if not expressions:
            raise ValueError("a policy must contain at least one condition")
        return tuple(expressions)

    def expression(self, *parts):
        if len(parts) == 3:
            entity, operator, value = parts
            return Condition(str(entity), None, str(operator), value)
        entity, attribute, operator, value = parts
        return Condition(str(entity), str(attribute), str(operator), value)

    def obligation(self, state_value):
        return state_value

    def effect(self, effect_value):
        return str(effect_value)


class PacaCompiler:
    """Parser and emitters for a small, explicitly limited policy language."""

    def __init__(self):
        self.parser = Lark(
            alfa_grammar, parser="lalr", transformer=AlfaTreeBuilder()
        )

    def compile_to_ast(self, text: str) -> PolicyAST:
        parsed = self.parser.parse(text)
        ast = parsed.children[0]
        if not isinstance(ast, PolicyAST):
            raise ValueError("policy parser did not produce a PolicyAST")
        return ast

    @staticmethod
    def _require_supported(ast: PolicyAST) -> None:
        if ast.obligation is not None:
            raise NotImplementedError(
                "verify_state obligations are parsed but are not implemented "
                "by the Cedar/ASP emitters"
            )

    @staticmethod
    def _cedar_value(value: str) -> str:
        return json.dumps(value, ensure_ascii=True)

    @staticmethod
    def _asp_value(value: str) -> str:
        return json.dumps(value, ensure_ascii=True)

    def emit_cedar(self, ast: PolicyAST) -> str:
        self._require_supported(ast)
        effect = "forbid" if ast.effect == "deny" else "permit"
        conditions = []
        for condition in ast.conditions:
            value = self._cedar_value(condition.value)
            if condition.entity == "provenance":
                lhs = "context.provenance"
            elif condition.entity == "user" and condition.attribute:
                lhs = f"principal.{condition.attribute}"
            else:
                raise NotImplementedError(
                    f"Cedar mapping is not defined for {condition.entity!r}"
                )
            conditions.append(f"{lhs} {condition.operator} {value}")
        action = self._cedar_value(ast.action)
        joined = " && ".join(f"({item})" for item in conditions)
        return (
            f'{effect} (principal, action == Action::{action}, resource) '
            f"when {{ {joined} }};"
        )

    def emit_asp(self, ast: PolicyAST) -> str:
        self._require_supported(ast)
        if not ast.action.isidentifier():
            raise ValueError("ASP action identifiers must be valid identifiers")
        atoms = [f"action_{ast.action}"]
        for condition in ast.conditions:
            value = self._asp_value(condition.value)
            if condition.entity == "provenance":
                predicate = "provenance"
            elif condition.entity == "user" and condition.attribute:
                if not condition.attribute.isidentifier():
                    raise ValueError("ASP attribute must be a valid identifier")
                predicate = f"user_{condition.attribute}"
            else:
                raise NotImplementedError(
                    f"ASP mapping is not defined for {condition.entity!r}"
                )
            atom = f'{predicate}(agent, {value})'
            atoms.append(f"not {atom}" if condition.operator == "!=" else atom)
        return f"{ast.effect} :- {', '.join(atoms)}."
