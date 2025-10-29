from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from phishing_logic import predict_email
import os

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.respond_with_html()
        elif self.path.startswith("/static/"):
            self.serve_static_file()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            parsed = urllib.parse.parse_qs(post_data.decode())
            email_text = parsed.get("email_content", [""])[0]

            prediction_result = predict_email(email_text)
            self.respond_with_html(prediction_result)

    def respond_with_html(self, result_html=""):
        with open("templates/index.html", "r") as f:
            html_content = f.read().replace("%RESULT%", result_html)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html_content.encode())

    def serve_static_file(self):
        file_path = self.path.lstrip("/")
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                self.send_response(200)
                self.send_header("Content-type", "text/css")
                self.end_headers()
                self.wfile.write(f.read())
        else:
            self.send_error(404)

if __name__ == "__main__":
    print("Serving on http://localhost:8080")
    server = HTTPServer(("localhost", 8080), SimpleHandler)
    server.serve_forever()
