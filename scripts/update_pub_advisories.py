#!/usr/bin/env python3
"""Refresh dart-lang/src/main/resources/security/pub-advisories.json from the OSV 'Pub' ecosystem dump.

Run from the repo root: python3 scripts/update_pub_advisories.py
The plugin matches pubspec.lock against this snapshot offline, so re-run and release to pick up new advisories.
"""
import io, json, urllib.request, zipfile

URL = "https://osv-vulnerabilities.storage.googleapis.com/Pub/all.zip"
OUT = "dart-lang/src/main/resources/security/pub-advisories.json"
SEVERITY = {"CRITICAL": "BLOCKER", "HIGH": "CRITICAL", "MODERATE": "MAJOR", "MEDIUM": "MAJOR", "LOW": "MINOR"}

out = []
with zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(URL, timeout=60).read())) as z:
    for name in sorted(z.namelist()):
        adv = json.loads(z.read(name))
        for aff in adv.get("affected", []):
            if aff.get("package", {}).get("ecosystem") != "Pub":
                continue
            ranges = [{k: v for ev in r["events"] for k, v in ev.items()}
                      for r in aff.get("ranges", []) if r.get("type") in ("ECOSYSTEM", "SEMVER")]
            out.append({
                "id": adv["id"],
                "aliases": adv.get("aliases", []),
                "summary": adv.get("summary", ""),
                "severity": SEVERITY.get(adv.get("database_specific", {}).get("severity", "").upper(), "MAJOR"),
                "package": aff["package"]["name"],
                "ranges": ranges,
                "versions": aff.get("versions", []),
            })
with open(OUT, "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")
print(f"{len(out)} package advisories -> {OUT}")
