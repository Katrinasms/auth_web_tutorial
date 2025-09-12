"""Very basic web server to handle GET and POST requests."""
from http.server import SimpleHTTPRequestHandler
import json
import socketserver
from typing import Dict, Optional, Tuple
import urllib.parse
from urllib.parse import parse_qs

from google.auth.transport import requests as google_auth_requests
from google.oauth2 import id_token


""" NOTE: You'll need to change this """
CLIENT_ID = (
    "872632489535-0dc0dehepucsopm3pqdpdkuq7n4t7ump.apps.googleusercontent.com"
)

""" these may change for a Cloud IDE, but good as-is for local termainals """
SERVER_ADDRESS = "0.0.0.0"
PORT = 3000
TARGET_HTML_PAGE_URL = f"http://localhost:{PORT}/"
""" and this is the end of constants you might need to change """

HTTP_STATUS_OK = 200
HTTP_STATUS_BAD_REQUEST = 400
HTTP_STATUS_UNAUTHORIZED = 401
HTTP_STATUS_INTERNAL_SERVER_ERROR = 500
HTTP_STATUS_FOUND = 303  # For redirection after decode and verify
OIDC_SERVER = "accounts.google.com"


class OIDCJWTReceiver(SimpleHTTPRequestHandler):
  """Request handler to securely process a Google ID token response."""

  def _validate_csrf(self, request_parameters: Dict) -> Tuple[bool, str]:
    """Validates the g_csrf_token to protect against CSRF attacks."""
    csrf_token_body = request_parameters.get("g_csrf_token")
    if not csrf_token_body:
      return False, "g_csrf_token not found in POST body."

    csrf_token_cookie = None
    cookie_header = self.headers.get("Cookie")
    if cookie_header:
      cookie_pairs = (c.split("=", 1) for c in cookie_header.split(";"))
      cookies = {k.strip(): v.strip() for k, v in cookie_pairs}
      csrf_token_cookie = cookies.get("g_csrf_token")
    if not csrf_token_cookie:
      return False, "g_csrf_token not found in cookie."

    if csrf_token_body != csrf_token_cookie:
      return False, "CSRF token mismatch."

    return True, "CSRF token validated successfully."

  def _parse_and_validate_credential(
      self, request_parameters: Dict
  ) -> Optional[Tuple[Optional[Dict], str]]:
    """Parse POST data, extract, decode and validate user credential."""
    credential = request_parameters.get("credential")
    if not credential:
      return None, "Credential not provided"

    try:
      id_info = id_token.verify_oauth2_token(
          credential, google_auth_requests.Request(), CLIENT_ID
      )
      return id_info, ""
    except ValueError as e:
      return None, f"Error during JWT decode: {e}"
    except Exception as e:
      return None, f"Unexpected error during credential validation: {e}"

  def _redirect_to_html(self, response_data: Dict) -> None:
    """Redirect to the target HTML page with data in the URL fragment."""
    try:
      json_data = json.dumps(response_data)
      encoded_data = urllib.parse.quote(json_data)
      redirect_url = f"http://localhost:{PORT}/#data={encoded_data}"
      self.send_response(HTTP_STATUS_FOUND)
      self.send_header("Location", redirect_url)
      self.send_header("Connection", "close")
      self.end_headers()
    except Exception as e:
      print(f"An error occurred during redirection: {e}")
      self.send_response(HTTP_STATUS_INTERNAL_SERVER_ERROR)
      self.send_header("Content-type", "text/plain")
      self.send_header("Connection", "close")
      self.end_headers()
      self.wfile.write(f"A redirect error occurred: {e}".encode("utf-8"))

  def _send_bad_request(self, message: str) -> None:
    """Sends a 400 Bad Request response."""
    self.send_response(HTTP_STATUS_BAD_REQUEST)
    self.send_header("Content-type", "text/plain")
    self.send_header("Connection", "close")
    self.end_headers()
    self.wfile.write(message.encode("utf-8"))

  def do_POST(self):
    """Handle POST requests for the /user-login path."""
    if self.path != "/user-login":
      self.send_error(404, "File not found")
      return

    try:
      content_length = int(self.headers.get("Content-Length", 0))
      post_data_bytes = self.rfile.read(content_length)
      post_data_str = post_data_bytes.decode("utf-8")
      request_parameters = {
          key: val[0]
          for key, val in parse_qs(post_data_str).items()
          if len(val) == 1
      }

      csrf_valid, csrf_message = self._validate_csrf(request_parameters)
      if not csrf_valid:
        print(f"CSRF verify failure: {csrf_message}")
        self._send_bad_request(f"CSRF verify failure: {csrf_message}")
        return

      decoded_id_token, error_message = self._parse_and_validate_credential(
          request_parameters
      )

      response_data = {}
      if decoded_id_token:
        response_data["status"] = "success"
        response_data["message"] = decoded_id_token
      elif error_message:
        response_data["status"] = "error"
        response_data["message"] = error_message
      else:
        response_data["status"] = "error"
        response_data["message"] = "Unknown error during JWT validation"

      self._redirect_to_html(response_data)

    except Exception as e:
      self._redirect_to_html(
          {"status": "error", "error_message": f"Internal server error: {e}"}
      )


with socketserver.TCPServer(("", PORT), OIDCJWTReceiver) as httpd:
  print(
      f"Serving HTTP on {SERVER_ADDRESS} port"
      f" {PORT} (http://{SERVER_ADDRESS}:{PORT}/)"
  )
  httpd.serve_forever()
