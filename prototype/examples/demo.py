from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from paca_mvp import AuthorizationEngine, Policy, AuthorizationError

policy = Policy.from_dict({
    "version": "demo-v1",
    "rules": [
        {"id": "analyst_reads_owned_file", "effect": "permit", "action": "file.read",
         "conditions": [
             {"path": "user.role", "op": "eq", "value": "analyst"},
             {"path": "resource.owner", "op": "eq", "value_from_path": "user.id"},
         ]},
        {"id": "block_file_delete", "effect": "deny", "action": "file.delete", "conditions": []},
    ],
})
engine = AuthorizationEngine(policy)
context = {"user": {"id": "user-17", "role": "analyst"}, "resource": {"owner": "user-17"}}
operation_args = {"path": "report-1", "mode": "read"}
decision = engine.authorize_operation("demo-user", "file.read", "file:report-1", operation_args, context)
print("Read decision:", decision.reason)
print("Effect result:", engine.execute_operation(decision.permit_id, "demo-user", "file.read", "file:report-1", operation_args, context,
                                                 lambda: "SIMULATED: report content returned"))
second = engine.authorize_operation("demo-user", "file.read", "file:report-1", operation_args, context)
try:
    engine.execute_operation(second.permit_id, "demo-user", "file.delete", "file:report-1", operation_args, context, lambda: "THIS MUST NEVER RUN")
except AuthorizationError as exc:
    print("Action substitution blocked:", exc)
confused_context = {"role": "analyst", "user": {"id": "user-17"},
                    "resource": {"owner": "user-17"}}
print("Missing-attribute decision:",
      engine.authorize("file.read", "file:report-1", confused_context).reason)
