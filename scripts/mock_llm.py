"""Fake OpenAI-compatible LLM for testing the firewall. Standard library only.

Run:   python scripts/mock_llm.py            (listens on 0.0.0.0:9000)
Then set TARGET_LLM_BASE_URL=http://host.docker.internal:9000/v1 in .env.

It prints every prompt it receives, so you can prove that blocked prompts
never reach the downstream model.

Trigger words in the user's message change the reply:
  leak-test   -> reply contains an email, an API key and a card number
                 (should be caught or redacted by the output scanner)
  anything else -> a harmless reply
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
LEAKY = ("Sure! Contact anna.k@acme.com and use the key sk-live-9f2a41c7d8e5b6a1c3f4 "
         "or card 4111 1111 1111 1111.")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._send(200, {"status": "mock llm ok"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "bad json"})
        messages = payload.get("messages") or []
        last = next((m.get("content", "") for m in reversed(messages) if m.get("role") == "user"), "")
        print(f"[{time.strftime('%H:%M:%S')}] RECEIVED: {last!r}", flush=True)
        reply = LEAKY if "leak-test" in str(last) else "Hello from the mock LLM. Your request reached me."
        self._send(200, {
            "id": "chatcmpl-mock", "object": "chat.completion", "created": int(time.time()),
            "model": payload.get("model", "mock"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 12, "total_tokens": 17},
        })

    def log_message(self, *args):  # silence default access log
        pass


if __name__ == "__main__":
    print(f"mock LLM listening on 0.0.0.0:{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()