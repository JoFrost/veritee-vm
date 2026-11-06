"""HTTPS transport with an explicit TCP address and normal hostname verification."""
import http.client


class ResolvedHttpsConnection(http.client.HTTPSConnection):
    """HTTPS connection with separate TLS and TCP destination hostnames."""

    def __init__(self, server_hostname: str, resolved_host: str, **kwargs):
        self.resolved_host = resolved_host
        super().__init__(server_hostname, **kwargs)

    def connect(self):
        server_hostname = self.host
        self.host = self.resolved_host
        try:
            http.client.HTTPConnection.connect(self)
        finally:
            self.host = server_hostname
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)
