"""Shared local-container MCP smoke assertions; no credentials are logged."""
import json
import urllib.error
import urllib.request


def request(base, method, params=None, token=None):
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    req = urllib.request.Request(base + "/mcp", data=body, headers=headers)
    try:
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=45)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read()
        if response.status != 200:
            return response.status, None
        return response.status, json.loads(data)


def call(base, name, arguments, token=None, *, succeeds=True):
    status, body = request(base, "tools/call", {"name": name, "arguments": arguments}, token)
    if status != 200 or not isinstance(body, dict) or "result" not in body:
        raise RuntimeError("MCP tool response failed: " + name)
    result = body["result"]
    if bool(result.get("isError")) == succeeds:
        raise RuntimeError("MCP tool outcome differs: " + name)
    return result


def text(result):
    return "\n".join(item["text"] for item in result.get("content", []) if item.get("type") == "text")


def verify_sections(base, conversion, markdown, token=None):
    selectors = []
    spans = []
    for kind in ("sections", "blocks"):
        inventory = call(base, "list", {"kind": kind, "conversion_id": conversion}, token)["structuredContent"]
        entries = inventory["items"][:2]
        if kind == "blocks" and not entries:
            raise RuntimeError("MCP block inventory missing")
        for span in entries:
            selectors.append({"kind": kind[:-1], "id": span["id"]})
            spans.append(span)
    result = call(base, "read-section", {"conversion_id": conversion, "selectors": selectors}, token)
    data = result["structuredContent"]
    if json.loads(text(result)) != data or data["conversion_id"] != conversion:
        raise RuntimeError("MCP section response differs")
    source = markdown.encode("utf-8")
    if len(data["results"]) != len(selectors):
        raise RuntimeError("MCP section result count differs")
    total = 0
    for item, selector, span in zip(data["results"], selectors, spans):
        expected = source[span["start"]:span["end"]]
        if item["selector"] != selector or item["span"] != span or item["text"].encode("utf-8") != expected or item["bytes"] != len(expected):
            raise RuntimeError("MCP section source slice differs")
        total += len(expected)
    if data["bytes"] != total:
        raise RuntimeError("MCP section byte total differs")
    return selectors


def exercise(base, conversion, markdown, token=None, other_token=None):
    status, body = request(base, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "pdf2md-smoke", "version": "1"}}, token)
    if status != 200 or body.get("result", {}).get("protocolVersion") != "2025-11-25":
        raise RuntimeError("MCP initialization failed")
    status, body = request(base, "tools/list", token=token)
    expected = {"list", "read", "read-page", "read-section", "table", "rg", "count", "size"}
    if status != 200 or {tool["name"] for tool in body.get("result", {}).get("tools", [])} != expected:
        raise RuntimeError("MCP tool discovery differs")
    read = call(base, "read", {"conversion_id": conversion}, token)
    # Metadata may be separate content; one text block must be the exact artifact.
    if not any(item.get("text") == markdown for item in read.get("content", [])):
        raise RuntimeError("MCP read did not return complete stored Markdown")
    call(base, "list", {"kind": "documents"}, token)
    call(base, "list", {"kind": "conversions"}, token)
    selectors = verify_sections(base, conversion, markdown, token)
    page = call(base, "read-page", {"conversion_id": conversion, "pages": "1"}, token)
    if "Conversion smoke test" not in text(page) + json.dumps(page.get("structuredContent", {})):
        raise RuntimeError("MCP page text missing")
    call(base, "table", {"conversion_id": conversion}, token)
    counts = call(base, "count", {"conversion_id": conversion}, token)["structuredContent"]
    sizes = call(base, "size", {"conversion_id": conversion}, token)["structuredContent"]
    expected_lines = markdown.count("\n") + int(bool(markdown) and not markdown.endswith("\n"))
    if counts["results"][0]["value"] != expected_lines or sizes["results"][0]["value"] != len(markdown.encode()):
        raise RuntimeError("MCP whole-file measurements differ")
    matches = call(base, "rg", {"pattern": "Conversion smoke test", "conversion_ids": [conversion], "literal": True}, token)
    if "Conversion smoke test" not in json.dumps(matches):
        raise RuntimeError("MCP ripgrep match missing")
    if other_token:
        call(base, "read", {"conversion_id": conversion}, other_token, succeeds=False)
        call(base, "read-section", {"conversion_id": conversion, "selectors": selectors}, other_token, succeeds=False)
        result = call(base, "rg", {"pattern": "Conversion smoke test", "literal": True}, other_token)
        if conversion in json.dumps(result):
            raise RuntimeError("MCP search crossed user workspaces")
    print("PASS eight MCP tools, whole Markdown, indexed pages and sections, ripgrep" + (" and OIDC isolation" if other_token else ""), flush=True)
