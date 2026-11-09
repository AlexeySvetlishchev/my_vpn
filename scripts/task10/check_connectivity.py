"""Fixed public TLS probe, no credentials or Telegram method calls."""
import json,socket,ssl,time
host='api.telegram.org'
for family,label in [(socket.AF_INET,'IPv4'),(socket.AF_INET6,'IPv6')]:
    started=time.monotonic()
    try:
        rows=socket.getaddrinfo(host,443,family,socket.SOCK_STREAM)
        sock=socket.socket(family,socket.SOCK_STREAM);sock.settimeout(6)
        try:
            sock.connect(rows[0][4])
            with ssl.create_default_context().wrap_socket(sock,server_hostname=host):pass
        finally:sock.close()
        print(json.dumps({'family':label,'tls':True,'seconds':round(time.monotonic()-started,2)}))
    except Exception as exc:
        print(json.dumps({'family':label,'tls':False,'category':type(exc).__name__,
                          'errno':getattr(exc,'errno',None),'seconds':round(time.monotonic()-started,2)}))
