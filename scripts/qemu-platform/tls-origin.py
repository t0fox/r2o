# TLS-ответчик из test-geneva-midpoint-netns.sh.
import socket
import ssl
import sys
import threading

root = sys.argv[1]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
context.load_cert_chain(f"{root}/cert.pem", f"{root}/key.pem")
def serve(peer):
    with peer:
        peer.settimeout(2)
        try:
            with context.wrap_socket(peer, server_side=True) as tls:
                if not tls.recv(4096).startswith(b"GET "):
                    return
                body = b"verified LAN/WAN response\n"
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                            str(len(body)).encode() + b"\r\n\r\n" + body)
                tls.unwrap().close()
        except (TimeoutError, OSError):
            pass
ipv6 = sys.argv[2:] == ["ipv6"]
with socket.create_server(("::" if ipv6 else "0.0.0.0", 443),
                          family=socket.AF_INET6 if ipv6 else socket.AF_INET) as listener:
    while True:
        peer, _ = listener.accept()
        threading.Thread(target=serve, args=(peer,), daemon=True).start()
