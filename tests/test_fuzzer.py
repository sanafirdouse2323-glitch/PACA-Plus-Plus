"""Regression tests for the supported PACA policy-subset compiler.

These tests validate parsing and generated-text invariants. They deliberately do
not claim semantic equivalence between Cedar and ASP; that requires executing
both backends against a shared, independently specified test corpus.
"""
import unittest

from compiler.transpiler import PacaCompiler


class CompilerSubsetTests(unittest.TestCase):
    def setUp(self):
        self.compiler = PacaCompiler()

    def test_preserves_all_and_conditions_in_ast_and_both_emitters(self):
        source = r'''
        policy RestrictExport {
            target: action == "readFile"
            condition: user.role != "admin" AND provenance == "trusted"
            effect: deny
        }
        '''
        ast = self.compiler.compile_to_ast(source)
        self.assertEqual(len(ast.conditions), 2)
        self.assertEqual(ast.conditions[0].entity, "user")
        self.assertEqual(ast.conditions[0].attribute, "role")
        self.assertEqual(ast.conditions[0].operator, "!=")
        self.assertEqual(ast.conditions[1].entity, "provenance")
        cedar = self.compiler.emit_cedar(ast)
        asp = self.compiler.emit_asp(ast)
        self.assertIn("principal.role !=", cedar)
        self.assertIn("context.provenance ==", cedar)
        self.assertIn("user_role(agent, \\"admin\\")", asp)
        self.assertIn("not provenance(agent, \\"trusted\\")", asp)

    def test_decodes_and_safely_reescapes_string_values(self):
        source = r'''
        policy Escaping {
            target: action == "readFile"
            condition: user.role == "ops \\"blue\\""
            effect: permit
        }
        '''
        ast = self.compiler.compile_to_ast(source)
        self.assertEqual(ast.conditions[0].value, 'ops "blue"')
        self.assertIn(r'principal.role == "ops \\"blue\\""', self.compiler.emit_cedar(ast))
        self.assertIn(r'user_role(agent, "ops \\"blue\\"")', self.compiler.emit_asp(ast))

    def test_obligation_is_preserved_and_emitters_refuse_to_ignore_it(self):
        source = r'''
        policy WithObligation {
            target: action == "readFile"
            condition: user.role == "admin"
            obligation: verify_state("file_system_unchanged")
            effect: permit
        }
        '''
        ast = self.compiler.compile_to_ast(source)
        self.assertEqual(ast.obligation, "file_system_unchanged")
        with self.assertRaises(NotImplementedError):
            self.compiler.emit_cedar(ast)
        with self.assertRaises(NotImplementedError):
            self.compiler.emit_asp(ast)

    def test_empty_or_unparseable_policy_is_rejected(self):
        with self.assertRaises(Exception):
            self.compiler.compile_to_ast("not a policy")

    def test_unsupported_entity_mapping_is_not_silently_emitted(self):
        source = r'''
        policy ResourceCondition {
            target: action == "readFile"
            condition: resource.owner == "sana"
            effect: permit
        }
        '''
        ast = self.compiler.compile_to_ast(source)
        with self.assertRaises(NotImplementedError):
            self.compiler.emit_cedar(ast)
        with self.assertRaises(NotImplementedError):
            self.compiler.emit_asp(ast)


if __name__ == "__main__":
    unittest.main()
