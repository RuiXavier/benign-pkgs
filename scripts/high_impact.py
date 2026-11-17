"""The candidate lists: parses lib/top-dependent.js and lib/top-download.js of an unpacked npm-high-impact package
(read as text, never run) into work/high-impact.json."""
import json, re, sys

P, W = sys.argv[1], sys.argv[2]  # the unpacked package folder, the work folder
load = lambda f: re.findall(r"^\s*'([^']+)',?\s*$", open(f"{P}/lib/{f}").read(), re.M)
json.dump({"topDependent": load("top-dependent.js"), "topDownload": load("top-download.js")},
          open(f"{W}/high-impact.json", "w"))
