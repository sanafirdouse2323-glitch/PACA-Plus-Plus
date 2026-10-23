from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import httpx

from .auth import Principal


class AdapterNotFound(LookupError):
    """No explicitly configured enforcement adapter supports this operation."""


class EffectRejected(RuntimeError):
    """The adapter can prove the operation was rejected without a successful effect."""

    def __init__(self, code: str, status_code: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class EffectOutcomeUnknown(RuntimeError):
    """The external effect may have happened; automatic retry would be unsafe."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EffectRequest:
    execution_id: str
    principal: Principal
    action: str
    resource_id: str
    arguments: dict[str, Any]
    context: dict[str, Any]


class ExecutionAdapter:
    def supports(
        self, action: str, arguments: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        raise NotImplementedError

    def execute(self, request: EffectRequest) -> dict[str, Any]:
        raise NotImplementedError


class HttpAPIAdapter(ExecutionAdapter):
    """Call only server-configured API routes on a fixed upstream origin.

    Client data cannot choose the scheme, hostname, port, HTTP method, or path
    template. Mutating requests forward the stable PACA execution UUID as the
    upstream Idempotency-Key; upstream services must honor that contract.
    """

    _METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
    _ACTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]*$")

    def __init__(
        self,
        base_url: str,
        routes: dict[str, dict[str, Any]],
        timeout_seconds: float,
        bearer_token: str | None = None,
        client: httpx.Client | None = None,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("upstream_base_url_must_be_absolute_http_url")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("upstream_base_url_must_not_contain_credentials_or_query")
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.max_response_bytes = max_response_bytes
        self._routes: dict[str, dict[str, str]] = {}
        for action, raw in routes.items():
            if not self._ACTION_RE.fullmatch(action):
                raise ValueError("invalid_upstream_action")
            if not isinstance(raw, dict):
                raise ValueError("invalid_upstream_route")
            method = raw.get("method")
            path = raw.get("path")
            args_mode = raw.get("args_mode", "json" if method != "GET" else "query")
            if method not in self._METHODS:
                raise ValueError(f"unsupported_upstream_method_for_{action}")
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
                raise ValueError(f"upstream_path_must_be_absolute_path_for_{action}")
            if "?" in path or "#" in path or "://" in path or "\\" in path:
                raise ValueError(f"unsafe_upstream_path_for_{action}")
            if any(part in {".", ".."} for part in path.split("/")):
                raise ValueError(f"unsafe_upstream_path_for_{action}")
            if re.sub(r"\{resource_id\}", "", path).find("{") >= 0 or re.sub(r"\{resource_id\}", "", path).find("}") >= 0:
                raise ValueError(f"unsupported_path_template_for_{action}")
            if args_mode not in {"json", "query", "none"}:
                raise ValueError(f"invalid_args_mode_for_{action}")
            if method != "GET" and args_mode == "query":
                raise ValueError(f"mutating_route_cannot_use_query_arguments_for_{action}")
            self._routes[action] = {"method": method, "path": path, "args_mode": args_mode}
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def supports(
        self, action: str, arguments: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        return action in self._routes

    def execute(self, request: EffectRequest) -> dict[str, Any]:
        route = self._routes[request.action]
        path = route["path"].replace("{resource_id}", quote(request.resource_id, safe=""))
        url = self.base_url + path
        headers = {
            "Accept": "application/json",
            "X-PACA-Execution-ID": request.execution_id,
            "Idempotency-Key": request.execution_id,
            "X-PACA-Tenant-ID": request.principal.tenant_id,
        }
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        kwargs: dict[str, Any] = {"headers": headers}
        if route["args_mode"] == "json":
            kwargs["json"] = request.arguments
        elif route["args_mode"] == "query":
            kwargs["params"] = request.arguments

        try:
            response = self.client.request(route["method"], url, **kwargs)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise EffectOutcomeUnknown("upstream_transport_outcome_unknown") from exc

        if response.status_code >= 500:
            raise EffectOutcomeUnknown("upstream_server_outcome_unknown")
        if response.status_code >= 400:
            # This assumes the upstream's 4xx contract means the operation was not applied.
            raise EffectRejected("upstream_rejected", status_code=response.status_code)
        if not 200 <= response.status_code < 300:
            raise EffectOutcomeUnknown("upstream_non_success_response")

        summary: dict[str, Any] = {"status_code": response.status_code}
        content_type = response.headers.get("content-type", "").lower()
        if len(response.content) > self.max_response_bytes:
            summary["response_body_omitted"] = "size_limit"
        elif "application/json" in content_type:
            try:
                decoded = response.json()
            except ValueError:
                summary["response_body_omitted"] = "invalid_json"
            else:
                if isinstance(decoded, dict):
                    summary["body"] = decoded
                elif isinstance(decoded, list):
                    summary["body"] = decoded
                else:
                    summary["body"] = {"value": decoded}
        return summary

    def close(self) -> None:
        self.client.close()


class ToolRegistryAdapter(ExecutionAdapter):
    """Dispatch only explicitly registered in-process tool handlers."""

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[[dict[str, Any], EffectRequest], dict[str, Any]]] = {}

    def register(
        self,
        name: str,
        handler: Callable[[dict[str, Any], EffectRequest], dict[str, Any]],
    ) -> None:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", name):
            raise ValueError("invalid_tool_name")
        if name in self._handlers:
            raise ValueError("duplicate_tool_registration")
        if not callable(handler):
            raise ValueError("tool_handler_must_be_callable")
        self._handlers[name] = handler

    def supports(
        self, action: str, arguments: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        return (
            action == "tool.invoke"
            and isinstance(arguments.get("name"), str)
            and arguments["name"] in self._handlers
        )

    def execute(self, request: EffectRequest) -> dict[str, Any]:
        name = request.arguments.get("name")
        tool_input = request.arguments.get("input", {})
        handler = self._handlers.get(name) if isinstance(name, str) else None
        if handler is None:
            raise EffectRejected("tool_not_registered")
        if not isinstance(tool_input, dict):
            raise EffectRejected("tool_input_must_be_object")
        result = handler(tool_input, request)
        if not isinstance(result, dict):
            raise EffectOutcomeUnknown("tool_returned_non_object_result")
        try:
            json.dumps(result, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise EffectOutcomeUnknown("tool_returned_non_json_result") from exc
        return result


class SandboxedFileAdapter(ExecutionAdapter):
    """Linux/POSIX file read and create operations confined below a configured root.

    Resource paths come from trusted resource metadata, never from the request body.
    Each path component is opened relative to a directory descriptor with O_NOFOLLOW.
    Creation uses a fully written temporary file and a no-overwrite hard link.
    """

    def __init__(self, root: str, max_file_bytes: int = 1_000_000) -> None:
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise RuntimeError("sandboxed_file_adapter_requires_posix_nofollow")
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("file_root_must_be_directory")
        self.max_file_bytes = max_file_bytes

    def supports(
        self, action: str, arguments: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        resource = context.get("resource")
        attributes = resource.get("attributes") if isinstance(resource, dict) else None
        return (
            action in {"file.read", "file.create"}
            and isinstance(resource, dict)
            and resource.get("kind") == "file"
            and isinstance(attributes, dict)
            and isinstance(attributes.get("relative_path"), str)
        )

    def execute(self, request: EffectRequest) -> dict[str, Any]:
        relative_path = request.context["resource"]["attributes"]["relative_path"]
        parent_fd, leaf = self._open_parent(relative_path)
        try:
            if request.action == "file.read":
                return self._read(parent_fd, leaf, request.resource_id)
            if request.action == "file.create":
                return self._create(parent_fd, leaf, request)
            raise EffectRejected("unsupported_file_operation")
        finally:
            os.close(parent_fd)

    def _open_parent(self, relative_path: str) -> tuple[int, str]:
        if (
            not relative_path
            or relative_path.startswith("/")
            or "\\" in relative_path
            or "\x00" in relative_path
        ):
            raise EffectRejected("unsafe_resource_path")
        parts = relative_path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise EffectRejected("unsafe_resource_path")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in parts[:-1]:
                child_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = child_fd
            return fd, parts[-1]
        except OSError as exc:
            os.close(fd)
            raise EffectRejected("resource_path_unavailable") from exc

    def _read(self, parent_fd: int, leaf: str, resource_id: str) -> dict[str, Any]:
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            raise EffectRejected("file_not_readable") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise EffectRejected("resource_not_regular_file")
            if info.st_size > self.max_file_bytes:
                raise EffectRejected("file_size_limit_exceeded")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65536, self.max_file_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > self.max_file_bytes:
                    raise EffectRejected("file_size_limit_exceeded")
            content_bytes = b"".join(chunks)
            try:
                text = content_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise EffectRejected("file_not_utf8_text") from exc
            return {
                "resource_id": resource_id,
                "content": text,
                "bytes_read": len(content_bytes),
                "sha256": hashlib.sha256(content_bytes).hexdigest(),
            }
        finally:
            os.close(fd)

    def _create(self, parent_fd: int, leaf: str, request: EffectRequest) -> dict[str, Any]:
        if set(request.arguments) != {"content"} or not isinstance(request.arguments.get("content"), str):
            raise EffectRejected("file_create_requires_only_string_content")
        content = request.arguments["content"].encode("utf-8")
        if len(content) > self.max_file_bytes:
            raise EffectRejected("file_size_limit_exceeded")
        temp_name = ".paca-tmp-" + secrets.token_hex(12)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = -1
        published = False
        try:
            fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.link(
                temp_name,
                leaf,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            published = True
            os.unlink(temp_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return {
                "resource_id": request.resource_id,
                "created": True,
                "bytes_written": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        except FileExistsError as exc:
            raise EffectRejected("file_already_exists") from exc
        except OSError as exc:
            if published:
                raise EffectOutcomeUnknown("file_published_but_finalize_failed") from exc
            raise EffectRejected("file_create_failed") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                # The target may already have been linked successfully. Do not hide
                # the principal operation's outcome here.
                pass


class AdapterRouter:
    def __init__(self, adapters: list[ExecutionAdapter]) -> None:
        self.adapters = adapters

    def choose(
        self, action: str, arguments: dict[str, Any], context: dict[str, Any]
    ) -> ExecutionAdapter:
        supported = [
            adapter for adapter in self.adapters if adapter.supports(action, arguments, context)
        ]
        if not supported:
            raise AdapterNotFound("no_adapter_for_operation")
        if len(supported) > 1:
            raise RuntimeError("ambiguous_enforcement_adapter_configuration")
        return supported[0]

    def close(self) -> None:
        for adapter in self.adapters:
            close = getattr(adapter, "close", None)
            if callable(close):
                close()
