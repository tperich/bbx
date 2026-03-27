
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from .base import BaseCheck, CheckResult

class ReflectionCheck(BaseCheck):
    name = 'reflection_check'
    description = 'Send a harmless marker in query string and look for reflection'

    def run(self, asset, context):
        url = asset['value']
        host = urlparse(url).hostname or asset.get('host') or ''
        context.ensure_allowed(host)
        marker='bbmarker123xyz'; parsed=urlparse(url); params=dict(parse_qsl(parsed.query)); params['bb_test']=marker
        target=urlunparse(parsed._replace(query=urlencode(params)))
        s=context.session(); context.bump(); resp=s.get(target, timeout=context.timeout, allow_redirects=False); context.throttle(); reflected = marker in resp.text
        findings=[]
        if reflected:
            findings.append({'severity':'info','title':'Marker reflected in response','details':f'Marker found in response body for {target}'})
        return CheckResult(status='done', summary='reflected' if reflected else 'not reflected', request_count=context.request_count, findings=findings, kv={'reflected':str(reflected).lower()})
