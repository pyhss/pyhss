# Copyright 2026 Bjoern Riemer <bjoern.riemer@fokus.fraunhofer.de>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal ASGI framework for 3GPP SBI servers (TS 29.500/29.501).

Serve the application with an ASGI server that supports HTTP/2 cleartext (h2c), e.g. hypercorn.
Bodies are validated and built with the generated 3GPP models in sbi.models, and errors are
returned as ProblemDetails (application/problem+json).
"""

import json
import re
import traceback
from urllib.parse import parse_qs

from pydantic import TypeAdapter, ValidationError
from sbi import models

JSON = "application/json"
JSON_PATCH = "application/json-patch+json"
MERGE_PATCH = "application/merge-patch+json"
PROBLEM_JSON = "application/problem+json"

TITLES = {
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    411: "Length Required",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
}


class SbiError(Exception):
    """Raise in a handler to answer with ProblemDetails (TS 29.571), e.g. cause USER_NOT_FOUND."""

    def __init__(self, status, cause=None, detail=None):
        super().__init__(detail or cause or str(status))
        self.status = status
        self.cause = cause
        self.detail = detail

    def problem(self):
        problem = {"title": TITLES.get(self.status, "Error"), "status": self.status}
        if self.detail:
            problem["detail"] = self.detail
        if self.cause:
            problem["cause"] = self.cause
        return models.ProblemDetails(**problem)


class Request:
    def __init__(self, method, path, query_string, headers, body):
        self.method = method
        self.path = path
        self.query = {k: v[0] for k, v in parse_qs(query_string.decode("latin-1")).items()}
        self.headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in headers}
        self.body = body

    @property
    def content_type(self):
        return self.headers.get("content-type", "").split(";", 1)[0].strip().lower()

    def json(self, content_types=(JSON,)):
        if not self.body:
            raise SbiError(400, "MANDATORY_IE_MISSING", "Request body is missing")
        if self.content_type not in content_types:
            raise SbiError(415, detail=f"Unsupported Content-Type: {self.content_type}")
        try:
            return json.loads(self.body)
        except ValueError as e:
            raise SbiError(400, "INVALID_MSG_FORMAT", f"Invalid JSON: {e}") from None

    def model(self, model, content_types=(JSON,)):
        """Parse the body and validate it against a 3GPP model (or e.g. list[models.PatchItem])."""
        data = self.json(content_types)
        try:
            if isinstance(model, type) and hasattr(model, "model_validate"):
                return model.model_validate(data)
            return TypeAdapter(model).validate_python(data)
        except ValidationError as e:
            raise SbiError(400, "MANDATORY_IE_INCORRECT", f"Invalid {getattr(model, '__name__', model)}: {e}") from None

    def query_list(self, name):
        """Comma separated query parameter (e.g. fields, dataset-names) as list, or None."""
        if name not in self.query:
            return None
        return [x.strip() for x in self.query[name].split(",") if x.strip()]


class Response:
    def __init__(self, status=200, body=None, content_type=JSON, headers=None):
        self.status = status
        self.body = body
        self.content_type = content_type
        self.headers = headers or {}

    def encode(self):
        body = self.body
        if body is None:
            return b""
        if hasattr(body, "model_dump"):
            body = body.model_dump(mode="json", by_alias=True, exclude_unset=True)
        elif isinstance(body, list):
            body = [x.model_dump(mode="json", by_alias=True, exclude_unset=True) for x in body]
        return json.dumps(body, separators=(",", ":")).encode()


class Route:
    def __init__(self, method, template, handler, operation_id):
        self.method = method
        self.template = template
        self.handler = handler
        self.operation_id = operation_id
        pattern = re.sub(r"\{([A-Za-z0-9_-]+)\}", lambda m: f"(?P<{m.group(1).replace('-', '_')}>[^/]+)", template)
        self.regex = re.compile(f"^{pattern}$")


class SbiApp:
    """ASGI application serving the routes of one SBI service, e.g. base "/nudr-dr" with versions ["v1"].

    Routes are registered with the path template and operationId from the 3GPP OpenAPI spec:

        @app.route("GET", "/subscription-data/{ueId}/...", "QueryAuthSubsData")
        async def handler(request, ueId): ...
    """

    def __init__(self, base, versions, log=None):
        self.base = base
        self.versions = list(versions)
        self.routes = []
        self.log = log or (lambda level, message: None)

    def route(self, method, template, operation_id):
        def decorator(handler):
            self.routes.append(Route(method, template, handler, operation_id))
            return handler

        return decorator

    def match(self, method, path):
        """Returns (route, params), or raises SbiError 404/405."""
        prefix_match = re.match(f"^{re.escape(self.base)}/([^/]+)(/.*)$", path)
        if not prefix_match or prefix_match.group(1) not in self.versions:
            raise SbiError(404, "RESOURCE_URI_STRUCTURE_NOT_FOUND", f"Unknown API or version: {path}")
        resource = prefix_match.group(2)
        path_known = False
        for route in self.routes:
            params = route.regex.match(resource)
            if params:
                path_known = True
                if route.method == method:
                    return route, params.groupdict()
        if path_known:
            raise SbiError(405, detail=f"Method {method} not allowed for {path}")
        raise SbiError(404, "RESOURCE_URI_STRUCTURE_NOT_FOUND", f"Unknown resource: {path}")

    async def handle(self, request):
        try:
            route, params = self.match(request.method, request.path)
            response = await route.handler(request, **params)
        except SbiError as e:
            response = Response(e.status, e.problem(), PROBLEM_JSON)
        except Exception:
            self.log("error", f"Error handling {request.method} {request.path}: {traceback.format_exc()}")
            response = Response(500, SbiError(500, "SYSTEM_FAILURE").problem(), PROBLEM_JSON)
        self.log("debug", f"{request.method} {request.path} -> {response.status}")
        return response

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return

        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break

        request = Request(scope["method"], scope["path"], scope.get("query_string", b""), scope["headers"], body)
        response = await self.handle(request)
        payload = response.encode()
        headers = [(k.lower().encode(), str(v).encode()) for k, v in response.headers.items()]
        if payload:
            headers.append((b"content-type", response.content_type.encode()))
        await send({"type": "http.response.start", "status": response.status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})
