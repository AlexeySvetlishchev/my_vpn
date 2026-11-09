"""Small Telegram HTTPS client. Never expose request URLs or error bodies."""
import json
import re
import secrets
import socket
import ssl
import urllib.error
import urllib.request


class ApiError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ApiError('telegram_redirect_refused')


class Telegram:
    def __init__(self, token, opener=None):
        if not re.fullmatch(r'[0-9]{5,15}:[A-Za-z0-9_-]{30,100}', token):
            raise ApiError('invalid_token_format')
        self._token = token
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, payload=None, document=None):
        if method not in {'getMe','getWebhookInfo','getUpdates','sendMessage',
                          'answerCallbackQuery','sendDocument','sendPhoto','deleteMessage','editMessageText'}:
            raise ApiError('method_not_allowed')
        payload = dict(payload or {})
        if document is None:
            body = json.dumps(payload).encode()
            content_type = 'application/json'
        else:
            name, content = document
            photo=method=='sendPhoto'
            if (not isinstance(content, bytes) or len(content) > (524288 if photo else 16384) or
                    not re.fullmatch(r'[^\r\n"/\\]{1,100}\.'+('png' if photo else '(?:conf|vpn)'), name)):
                raise ApiError('invalid_document')
            boundary = secrets.token_hex(24)
            payload.update(protect_content=True)
            if not photo:payload['disable_content_type_detection']=True
            chunks = []
            for key, val in payload.items():
                text = json.dumps(val) if not isinstance(val,str) else val
                chunks.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"'
                               f'\r\n\r\n{text}\r\n').encode())
            field='photo' if photo else 'document'
            chunks += [(f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; '
                        f'filename="{name}"\r\nContent-Type: '+('image/png' if photo else 'application/octet-stream')+'\r\n\r\n').encode(),
                       content, f'\r\n--{boundary}--\r\n'.encode()]
            body = b''.join(chunks)
            content_type = 'multipart/form-data; boundary='+boundary
        try:
            req = urllib.request.Request('https://api.telegram.org/bot'+self._token+'/'+method,
                                         data=body,headers={'Content-Type':content_type})
            with self.opener.open(req, timeout=45) as response:
                raw = response.read(2*1024*1024+1)
            if len(raw)>2*1024*1024:raise ApiError('telegram_response_bound')
            result = json.loads(raw)
            if not result.get('ok'):raise ApiError('telegram_request_refused')
            return result['result']
        except urllib.error.HTTPError as exc:
            code=exc.code if type(exc.code)==int and 100<=exc.code<=599 else 0
            raise ApiError('telegram_http_'+str(code)) from None
        except urllib.error.URLError as exc:
            reason=exc.reason
            category=('telegram_timeout' if isinstance(reason,(TimeoutError,socket.timeout)) else
                      'telegram_dns_failure' if isinstance(reason,socket.gaierror) else
                      'telegram_tls_failure' if isinstance(reason,ssl.SSLError) else 'telegram_connection_failed')
            raise ApiError(category) from None
        except (TimeoutError,socket.timeout):
            raise ApiError('telegram_timeout') from None
        except Exception:
            # urllib errors include the token-bearing URL. Never chain/log it.
            raise ApiError('telegram_request_failed') from None
