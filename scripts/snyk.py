"""Stage C: the SNYK-JS advisory ids on Snyk's public page of each candidate (any version), 1 request/s, resumable."""
import json, os, re, sys, time, urllib.error, urllib.parse, urllib.request

W = sys.argv[1]
names = json.load(open(sys.argv[2]))  # only the candidates that passed every other check
os.makedirs(f"{W}/snyk", exist_ok=True)

for i, name in enumerate(names):
    out = f"{W}/snyk/{name.replace('/', '__')}.json"
    if os.path.exists(out):
        continue
    url = "https://security.snyk.io/package/npm/" + urllib.parse.quote(name, safe="")
    res = {"name": name, "status": None}
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (research package scan)"})
            with urllib.request.urlopen(req, timeout=60) as r:
                html = r.read().decode("utf-8", "replace")
            res["status"] = 200
            res["ids"] = sorted(set(re.findall(r"SNYK-JS-[A-Z0-9]+-\d+", html)))
            res["no_direct_text"] = "No direct vulnerabilities have been found" in html
            break
        except urllib.error.HTTPError as e:
            res["status"] = e.code
            if e.code == 404:
                break
            time.sleep(10 * (attempt + 1))
        except Exception as e:
            res["status"] = repr(e)
            time.sleep(10 * (attempt + 1))
    json.dump(res, open(out, "w"))
    if (i + 1) % 100 == 0:
        print(f"{i + 1}/{len(names)}", file=sys.stderr, flush=True)
    time.sleep(1)
print("finished", len(names), file=sys.stderr)
