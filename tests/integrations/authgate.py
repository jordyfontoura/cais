"""Stand-in identity provider speaking the forward-auth contract real providers use:
an anonymous request is redirected to a login page on another hostname, the login sets
a session cookie for the parent domain and redirects back, and an authenticated request
is approved with the user's name in a response header. It is not a real provider."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, quote, urlparse

COOKIE = "fixture_session=valid"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/verify":
            if COOKIE in self.headers.get("Cookie", ""):
                self.send_response(200)
                self.send_header("Remote-User", "demo")
            else:
                target = "https://{}{}".format(
                    self.headers.get("X-Forwarded-Host", ""), self.headers.get("X-Forwarded-Uri", "/"))
                self.send_response(302)
                self.send_header("Location", "https://login.example.org/login?rd=" + quote(target, safe=""))
        elif url.path == "/login":
            target = parse_qs(url.query).get("rd", ["https://login.example.org/"])[0]
            self.send_response(302)
            self.send_header("Set-Cookie", COOKIE + "; Domain=example.org; Path=/; Secure; HttpOnly")
            self.send_header("Location", target)
        else:
            self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


HTTPServer(("127.0.0.1", 9091), Handler).serve_forever()
