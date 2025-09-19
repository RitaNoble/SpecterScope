#!/usr/bin/env python3
"""
SpecterScope - Lightweight Reconnaissance Skeleton Tool
"""

import asyncio
import aiohttp
import dns.resolver
import whois
import json
import datetime
from dataclasses import dataclass, asdict
import argparse

# ---------- Data Classes ----------
@dataclass
class ReconResult:
    target: str
    dns_records: dict
    whois_data: dict
    http_headers: dict
    timestamp: datetime.datetime

# ---------- JSON Converter ----------
def json_converter(o):
    if isinstance(o, datetime.datetime):
        return o.isoformat()
    if isinstance(o, datetime.date):
        return o.isoformat()
    return str(o)

# ---------- Recon Functions ----------
async def fetch_http_headers(session, url):
    try:
        async with session.get(url, timeout=5) as resp:
            return dict(resp.headers)
    except Exception:
        return {}

async def dns_lookup(target):
    records = {}
    try:
        answers = dns.resolver.resolve(target, 'A')
        records['A'] = [r.to_text() for r in answers]
    except Exception:
        records['A'] = []
    try:
        answers = dns.resolver.resolve(target, 'MX')
        records['MX'] = [r.exchange.to_text() for r in answers]
    except Exception:
        records['MX'] = []
    return records

def whois_lookup(target):
    try:
        w = whois.whois(target)
        return {k: str(v) for k, v in w.items() if v}
    except Exception:
        return {}

async def recon_target(session, target):
    dns_records = await dns_lookup(target)
    whois_data = whois_lookup(target)
    http_headers = await fetch_http_headers(session, f"http://{target}")
    return ReconResult(
        target=target,
        dns_records=dns_records,
        whois_data=whois_data,
        http_headers=http_headers,
        timestamp=datetime.datetime.utcnow()
    )

# ---------- Main Async ----------
async def run_recon(targets, concurrency):
    results = []
    conn = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        sem = asyncio.Semaphore(concurrency)
        async def bound_recon(t):
            async with sem:
                return await recon_target(session, t)

        tasks = [bound_recon(t) for t in targets]
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            print(f"[INFO] Finished recon for {result.target}")
    return results

# ---------- CLI ----------
def run_cli():
    parser = argparse.ArgumentParser(description="SpecterScope - Recon Tool")
    parser.add_argument("-t", "--target", help="Single target domain")
    parser.add_argument("-l", "--list", help="File with target domains")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Concurrent requests")
    args = parser.parse_args()

    # Collect targets
    targets = []
    if args.target:
        targets = [args.target]
    elif args.list:
        with open(args.list) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        print("Please provide -t <target> or -l <file>")
        return

    print(f"[INFO] Starting SpecterScope recon for {len(targets)} target(s) with concurrency={args.concurrency}")

    # Run async loop
    reports = asyncio.run(run_recon(targets, args.concurrency))

    # Save JSON report
    with open("specterscope_report.json", "w") as f:
        json.dump([asdict(r) for r in reports], f, indent=2, default=json_converter)

    print("[INFO] Recon complete. Results saved to specterscope_report.json")

# ---------- Entry ----------
if __name__ == "__main__":
    run_cli()

