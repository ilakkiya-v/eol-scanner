"""Fake company LLM gateway that speaks the Anthropic Messages API, for testing the "gateway" connection offline.

Behaves like a strict corporate proxy: requires a Bearer or x-api-key credential and rejects unknown beta features
(the server-side refusal fallback), so the scanner's plain-request retry gets exercised.

Run: python tests/fake_gateway.py 8898   then set the gateway URL to http://127.0.0.1:8898 and ANTHROPIC_AUTH_TOKEN=test
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SEEN = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        SEEN.append({"path": self.path, "beta": self.headers.get("anthropic-beta"), "model": req.get("model")})
        if not (self.headers.get("authorization", "").startswith("Bearer ") or self.headers.get("x-api-key")):
            return self._send(401, {"type": "error", "error": {"type": "authentication_error", "message": "no credential"}})
        if not self.path.split("?")[0].endswith("/v1/messages"):
            return self._send(404, {"type": "error", "error": {"type": "not_found_error", "message": self.path}})
        if self.headers.get("anthropic-beta") or "fallbacks" in req:
            return self._send(400, {"type": "error", "error": {"type": "invalid_request_error",
                                                               "message": "gateway: unknown beta / extra field 'fallbacks'"}})
        self._send(200, {"id": "msg_fake", "type": "message", "role": "assistant", "model": req.get("model"),
                         "content": [{"type": "text", "text": "OK"}], "stop_reason": "end_turn", "stop_sequence": None,
                         "usage": {"input_tokens": 10, "output_tokens": 1}})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8898
    print(f"fake gateway on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
