# Flow 02: Blend recon outputs with captured traffic

This is useful when you want one workspace with subdomains, alive hosts, crawled URLs, historical URLs, ports, and your own captured requests.

```bash
python3 bbx.py init acme
python3 bbx.py ingest-subfinder acme samples/subfinder.txt
python3 bbx.py ingest-httpx acme samples/httpx.jsonl
python3 bbx.py ingest-katana acme samples/katana.jsonl
python3 bbx.py ingest-gau acme samples/gau.txt
python3 bbx.py ingest-wayback acme samples/wayback.txt
python3 bbx.py ingest-naabu acme samples/naabu.txt
python3 bbx.py import-har acme samples/session.har
python3 bbx.py rank acme
```

Check likely interesting URLs and generate a graph:

```bash
python3 bbx.py interesting-urls acme --limit 20 --format csv
python3 bbx.py graph acme --format mermaid
```

Export tables for ad-hoc review:

```bash
python3 bbx.py export acme urls_discovered --format csv
python3 bbx.py export acme requests --format json
```
