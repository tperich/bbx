
from urllib.parse import urlparse
from .base import BaseCheck, CheckResult

class MethodDiffCheck(BaseCheck):
    name = 'method_diff'
    description = 'Compare basic HTTP method behavior'
    METHODS = ['GET','HEAD','OPTIONS','POST']

    def run(self, asset, context):
        url = asset['value']
        host = urlparse(url).hostname or asset.get('host') or ''
        context.ensure_allowed(host)
        s=context.session(); statuses={}; findings=[]
        for method in self.METHODS:
            context.bump(); resp=s.request(method, url, timeout=context.timeout, allow_redirects=False); context.throttle(); statuses[method]=resp.status_code
        if statuses.get('GET') in {401,403} and statuses.get('HEAD') == 200:
            findings.append({'severity':'low','title':'HEAD differs from GET','details':str(statuses)})
        return CheckResult(status='done', summary=str(statuses), request_count=context.request_count, findings=findings, kv={f'status_{k.lower()}':str(v) for k,v in statuses.items()})
