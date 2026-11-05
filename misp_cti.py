#!/usr/bin/env python3
"""Fetch CVEs, reports and threat context from OpenCTI -> cti.json (read-only)."""
import os, sys, json, time, requests
from datetime import datetime, timedelta, timezone
if os.environ.get("OPENCTI_VERIFY_TLS", "1").lower() in ("0", "false", "no"):
    requests.packages.urllib3.disable_warnings()
U = os.environ.get("OPENCTI_URL", "").rstrip("/")
T = os.environ.get("OPENCTI_TOKEN", "")
OUT = os.environ.get("CTI_OUT", "cti.json")
VERIFY = os.environ.get("OPENCTI_VERIFY_TLS", "1").lower() not in ("0", "false", "no")
DAYS = 30
H = {"Authorization": "Bearer " + T, "Content-Type": "application/json"}
SINCE = (datetime.now(timezone.utc) - timedelta(days=DAYS)).strftime("%Y-%m-%dT00:00:00.000Z")
FG = '{mode: and, filters: [{key: "%s", values: ["%s"], operator: gt}], filterGroups: []}'
diag = []


def q(name, query, quiet=False):
    try:
        r = requests.post(U + "/graphql", json={"query": query}, headers=H, verify=VERIFY, timeout=90)
        j = r.json()
        if j.get("errors") and not j.get("data"):
            raise RuntimeError(j["errors"][0].get("message", "")[:110])
        if not quiet:
            diag.append("%s: ok" % name)
        return j.get("data") or {}
    except Exception as e:
        m = "%s: ERROR %s" % (name, str(e)[:110])
        if m not in diag:
            diag.append(m)
        return {}


def nodes(d, key):
    return [e["node"] for e in ((d.get(key) or {}).get("edges") or [])]


def dist(name, rel, to, frag):
    d = q(name, '{ stixCoreRelationshipsDistribution(field: "internal_id", operation: count, '
                'relationship_type: "%s", toTypes: ["%s"], startDate: "%s", limit: 10) '
                '{ label value entity { %s } } }' % (rel, to, SINCE, frag))
    out = []
    for x in d.get("stixCoreRelationshipsDistribution") or []:
        e = x.get("entity") or {}
        nm = e.get("name") or x.get("label")
        if e.get("x_mitre_id"):
            nm = e["x_mitre_id"] + " " + nm
        out.append([nm, x.get("value")])
    return out


def main():
    if not U or not T:
        sys.exit("set OPENCTI_URL and OPENCTI_TOKEN")
    out = {"ts": int(time.time()), "days": DAYS, "stale": False}
    d = q("cves", '{ vulnerabilities(first: 40, orderBy: created, orderMode: desc, filters: %s) { edges { node { '
                  'name description created x_opencti_cvss_base_score x_opencti_cvss_base_severity '
                  'x_opencti_epss_score x_opencti_cisa_kev } } } }' % (FG % ("created", SINCE)))
    out["cves"] = [{"n": v["name"], "d": (v.get("description") or "")[:200], "t": v.get("created") or "",
                    "s": v.get("x_opencti_cvss_base_score"), "sev": v.get("x_opencti_cvss_base_severity") or "",
                    "e": v.get("x_opencti_epss_score"), "k": bool(v.get("x_opencti_cisa_kev"))}
                   for v in nodes(d, "vulnerabilities")]
    d = q("reports", '{ reports(first: 30, orderBy: published, orderMode: desc) { edges { node { id name description '
                     'published confidence createdBy { name } objectLabel { value } } } } }')
    reps = [{"id": r["id"], "n": r["name"], "t": r.get("published") or "", "d": (r.get("description") or "")[:240],
             "src": (r.get("createdBy") or {}).get("name") or "", "url": "", "conf": r.get("confidence"),
             "lab": [l["value"] for l in (r.get("objectLabel") or [])][:6],
             "act": [], "mal": [], "tech": [], "sec": [], "cve": []} for r in nodes(d, "reports")]
    d = q("report links", '{ reports(first: 30, orderBy: published, orderMode: desc) { edges { node { id '
                          'externalReferences(first: 1) { edges { node { source_name url } } } } } } }')
    ext = {}
    for r in nodes(d, "reports"):
        e = [x["node"] for x in (r.get("externalReferences") or {}).get("edges", [])]
        if e:
            ext[r["id"]] = e[0]
    kinds = {"IntrusionSet": "act", "ThreatActorGroup": "act", "Malware": "mal", "AttackPattern": "tech",
             "Sector": "sec", "Vulnerability": "cve"}
    for r in reps:
        r["url"] = (ext.get(r["id"]) or {}).get("url") or ""
        r["src"] = r["src"] or (ext.get(r["id"]) or {}).get("source_name") or ""
    for r in reps[:20]:
        d = q("report objects", '{ report(id: "%s") { objects(first: 100) { edges { node { __typename '
                                '... on IntrusionSet { name } ... on ThreatActorGroup { name } ... on Malware { name } '
                                '... on AttackPattern { name x_mitre_id } ... on Sector { name } '
                                '... on Vulnerability { name } } } } } }' % r["id"], True)
        for e in (((d.get("report") or {}).get("objects") or {}).get("edges") or []):
            n = e["node"]
            k = kinds.get(n.get("__typename"))
            nm = n.get("name")
            if k and nm:
                nm = (n.get("x_mitre_id") + " " + nm) if n.get("x_mitre_id") else nm
                if nm not in r[k]:
                    r[k].append(nm)
        for k in kinds.values():
            r[k] = r[k][:8]
    out["reports"] = reps
    out["sectors"] = dist("top sectors", "targets", "Sector", "... on Sector { name }")
    out["countries"] = dist("top countries", "targets", "Country", "... on Country { name }")
    out["tech"] = dist("top techniques", "uses", "Attack-Pattern", "... on AttackPattern { name x_mitre_id }")
    out["mal"] = dist("top malware", "uses", "Malware", "... on Malware { name }")
    d = q("actors", '{ intrusionSets(first: 12, orderBy: modified, orderMode: desc) { edges { node { name modified } } } }')
    out["actors"] = [[a["name"], a.get("modified") or ""] for a in nodes(d, "intrusionSets")]
    cnt = {}
    for k, key in [("reports", "published"), ("vulnerabilities", "created"), ("intrusionSets", "created"),
                   ("malwares", "created")]:
        d = q("count " + k, '{ %s(first: 1, filters: %s) { pageInfo { globalCount } } }' % (k, FG % (key, SINCE)), True)
        cnt[k] = ((d.get(k) or {}).get("pageInfo") or {}).get("globalCount")
    out["cnt"] = cnt
    old = {}
    try:
        old = json.load(open(OUT))
    except Exception:
        pass
    if not out["reports"] and not out["cves"] and old.get("reports"):
        old["stale"] = True
        out = old
    out["diag"] = diag
    with open(OUT + ".tmp", "w") as f:
        json.dump(out, f)
    os.replace(OUT + ".tmp", OUT)
    for x in diag:
        print("  " + x)
    print("cti.json written: %d CVEs, %d reports%s" % (len(out.get("cves", [])), len(out.get("reports", [])),
                                                       " (STALE cache)" if out.get("stale") else ""))


if __name__ == "__main__":
    main()
