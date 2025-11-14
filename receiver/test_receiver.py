#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        print(body.decode('utf-8', 'ignore'), flush=True)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args, **kwargs):
        pass  # silence default logging

if __name__ == '__main__':
    HTTPServer(('127.0.0.1', 9000), Handler).serve_forever()
