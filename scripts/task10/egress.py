"""Fixed Telegram connector. Root broker only; DNS and TCP fail closed via FR."""
import array
import http.client
import json
import secrets
import socket
import ssl
import struct
import time
import uuid
import urllib.error

MARK=0x704
HOST='api.telegram.org'
_cache=(0,[])

def marked_socket(kind,source):
    sock=socket.socket(socket.AF_INET,kind)
    try:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,MARK)
        sock.settimeout(8)
        sock.bind((source,0))
        return sock
    except BaseException:sock.close();raise

def dns_answers(data,ident):
    if len(data)<12:raise ValueError('dns_short')
    qid,flags,qd,an,_,_=struct.unpack('!6H',data[:12])
    if qid!=ident or flags&15 or flags&0x200 or not flags&0x8000 or qd!=1:
        raise ValueError('dns_response')
    def skip(pos):
        for _ in range(128):
            if pos>=len(data):raise ValueError('dns_bounds')
            n=data[pos]
            if n&0xc0==0xc0:
                if pos+2>len(data):raise ValueError('dns_bounds')
                return pos+2
            if n==0:return pos+1
            if n>63:raise ValueError('dns_label')
            pos+=n+1
        raise ValueError('dns_name')
    wire=b''.join(bytes([len(x)])+x.encode() for x in HOST.split('.'))+b'\0'
    if data[12:12+len(wire)+4]!=wire+struct.pack('!HH',1,1):raise ValueError('dns_question')
    pos=skip(12)+4;addresses=[]
    if an>64:raise ValueError('dns_count')
    for _ in range(an):
        pos=skip(pos)
        if pos+10>len(data):raise ValueError('dns_bounds')
        typ,cls,ttl,size=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10
        if pos+size>len(data):raise ValueError('dns_bounds')
        if typ==1 and cls==1 and size==4:addresses.append(socket.inet_ntoa(data[pos:pos+4]))
        pos+=size
    if not addresses:raise ValueError('dns_no_ipv4')
    return addresses[:16]

def resolve_telegram():
    global _cache
    if _cache[0]>time.monotonic():return _cache[1]
    ident=secrets.randbelow(65536)
    wire=b''.join(bytes([len(x)])+x.encode() for x in HOST.split('.'))+b'\0'
    query=struct.pack('!6H',ident,0x100,1,0,0,0)+wire+struct.pack('!HH',1,1)
    for resolver in ('9.9.9.9','149.112.112.112'):
        try:
            # TASK08's existing source/destination rules route these DNS queries
            # through FR, with terminal unreachable and WAN DROP safeguards.
            with marked_socket(socket.SOCK_DGRAM,'10.203.254.1') as sock:
                sock.connect((resolver,53));sock.send(query)
                addresses=dns_answers(sock.recv(4096),ident)
            _cache=(time.monotonic()+60,addresses);return addresses
        except (OSError,ValueError):continue
    raise OSError('telegram_dns_via_fr_unavailable')

def dial_telegram():
    for address in resolve_telegram():
        sock=None
        try:
            # Existing FR forwarding/NAT covers the client subnet, including
            # RU's already assigned local server address. No new peer or IP.
            sock=marked_socket(socket.SOCK_STREAM,'10.203.253.1')
            sock.connect((address,443));return sock
        except OSError:
            if sock:sock.close()
    raise OSError('telegram_tcp_via_fr_unavailable')

def request_fd(admin):
    request={'id':uuid.uuid4().hex,'admin':admin,'chat':admin,'action':'network.telegram','args':[]}
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(30);channel.connect('/run/vpn-task10-broker/manager.sock')
        channel.sendall(json.dumps(request).encode()+b'\n')
        data,ancillary,flags,_=channel.recvmsg(1024,socket.CMSG_SPACE(array.array('i').itemsize))
    fds=[]
    for level,kind,value in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
            values=array.array('i');values.frombytes(value[:len(value)//values.itemsize*values.itemsize]);fds.extend(values)
    try:
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or len(fds)!=1 or not json.loads(data).get('ok'):
            raise OSError('telegram_socket_refused')
        sock=socket.socket(fileno=fds.pop());sock.settimeout(45);return sock
    finally:
        import os
        for fd in fds:os.close(fd)

class Opener:
    """urllib-compatible HTTPS opener with an existing marked TCP socket.

    No host DNS, direct connect, proxies or redirects are available in this path.
    TLS hostname/certificate validation stays in the unprivileged bot process.
    """
    def __init__(self,connector):self.connector=connector
    def open(self,request,timeout=45):
        from urllib.parse import urlsplit
        parsed=urlsplit(request.full_url)
        if parsed.scheme!='https' or parsed.netloc!=HOST:raise OSError('fixed_host_only')
        connector=self.connector
        class Connection(http.client.HTTPSConnection):
            def connect(self):
                raw=connector()
                try:self.sock=self._context.wrap_socket(raw,server_hostname=HOST)
                except BaseException:raw.close();raise
        connection=Connection(HOST,timeout=timeout,context=ssl.create_default_context())
        try:
            headers=dict(request.header_items());headers['Connection']='close'
            connection.request('POST',parsed.path,body=request.data,headers=headers)
            response=connection.getresponse()
            if response.status>=300:
                status=response.status;response.close();connection.close()
                raise urllib.error.HTTPError(HOST,status,'',{},None)
            return response
        except BaseException:connection.close();raise
