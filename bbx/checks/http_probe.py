
from urllib.parse import urlparse
from .base import BaseCheck, CheckResult

class HttpProbeCheck(BaseCheck):
    name = 'http_probe'
    description = 'Fetch a URL and record basic metadata'

    def run(self, asset, context):
        url = asset['value']
        host = urlparse(url).hostname or asset.get('host') or ''
        context.ensure_allowed(host)
        s = context.session(); context.bump()
        resp = s.get(url, timeout=context.timeout, allow_redirects=False)
        context.throttle()
        return CheckResult(status='done', summary=f"{resp.status_code} {resp.headers.get('Content-Type','')}", request_count=context.request_count, kv={'status_code': str(resp.status_code), 'content_type': resp.headers.get('Content-Type','')})
