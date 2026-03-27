# Flow 01: HAR-first triage

Use this when you already explored the app manually and captured traffic.

```bash
python3 bbx.py init acme
python3 bbx.py import-har acme samples/session.har
python3 bbx.py rank acme
python3 bbx.py top acme --limit 15 --format json
```

Then tag the rows you care about:

```bash
python3 bbx.py tag-add acme request 1 authz
python3 bbx.py tag-add acme request 2 export --note "Might expose other tenant data"
python3 bbx.py tags acme
```

Create a finding draft once something is validated:

```bash
python3 bbx.py new-finding acme idor_invoice_access --title "Cross-account invoice access"
python3 bbx.py set-finding-status acme idor_invoice_access validated
```


## Reuse your filters with presets

```bash
python3 bbx.py preset-save acme authz --tag authz --min-score 20 --path-prefix /api/
python3 bbx.py top acme --preset authz
```
