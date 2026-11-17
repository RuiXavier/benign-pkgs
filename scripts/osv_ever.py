"""Stage A: every OSV advisory that ever affected each candidate name (any version)."""
import json, sys, urllib.request

W = sys.argv[1]  # work dir
hi = json.load(open(f"{W}/high-impact.json"))
dl, dep = set(hi["topDownload"]), set(hi["topDependent"])
# tiers in order: on both lists (most dependents first), dependents-only, then the 2,500 most downloaded downloads-only
tier = {}
for n in hi["topDependent"]:
    if n in dl and not n.startswith("@types/"):
        tier.setdefault(n, "both")
for n in hi["topDependent"]:
    if n not in dl and not n.startswith("@types/"):
        tier.setdefault(n, "dependents-only")
for n in [n for n in hi["topDownload"] if n not in dep and not n.startswith("@types/")][:2500]:
    tier[n] = "downloads-only"
cands = list(tier)


def post(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


ever = {}
for i in range(0, len(cands), 1000):
    chunk = cands[i:i + 1000]
    queries = [{"package": {"name": n, "ecosystem": "npm"}} for n in chunk]
    pending = list(range(len(chunk)))
    while pending:
        res = post("https://api.osv.dev/v1/querybatch", {"queries": [queries[j] for j in pending]})["results"]
        nxt = []
        for j, r in zip(pending, res):
            ever.setdefault(chunk[j], []).extend(v["id"] for v in r.get("vulns", []))
            if r.get("next_page_token"):
                queries[j]["page_token"] = r["next_page_token"]
                nxt.append(j)
        pending = nxt
    print(f"{i + len(chunk)}/{len(cands)}", file=sys.stderr)

json.dump({"candidates": cands, "tier": tier, "osv_ever": ever}, open(f"{W}/osv-ever.json", "w"))
clean = [n for n in cands if not ever[n]]
mal_only = [n for n in cands if ever[n] and all(v.startswith("MAL-") for v in ever[n])]
print("candidates", len(cands), "no advisory ever", len(clean), "only MAL ids", len(mal_only))
