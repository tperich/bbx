
from urllib.parse import urlparse
from .base import BaseCheck, CheckResult

class OpenApiFetchCheck(BaseCheck):
    name = 'openapi_fetch'
    description = 'Try common OpenAPI/Swagger paths'
    CANDIDATES = ['/openapi.json','/swagger.json','/api-docs','/v3/api-docs']

    def run(self, asset, context):
        url = asset['value'].rstrip('/')
        host = urlparse(url).hostname or asset.get('host') or ''
        context.ensure_allowed(host)
        s = context.session(); findings=[]
        for path in self.CANDIDATES:
            context.bump(); resp=s.get(url+path, timeout=context.timeout, allow_redirects=False); context.throttle()
            ctype=resp.headers.get('Content-Type','')
            if resp.status_code == 200 and ('json' in ctype.lower() or 'openapi' in resp.text.lower()):
                findings.append({'severity':'info','title':f'Potential API docs exposed at {path}','details':f'Status {resp.status_code}, content-type {ctype}'})
        return CheckResult(status='done', summary='checked common API doc paths', request_count=context.request_count, findings=findings)
