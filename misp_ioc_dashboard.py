#!/usr/bin/env python3
"""
ShadoWATCH: threat-intelligence dashboard for SOCs -> one self-contained HTML file (no CDN).
Sources: MISP (REST) for IOCs and events; optional OpenCTI context via cti.json (see misp_cti.py).
Tabs: Overview | IOCs (top IPs, hashes, domains/URLs) | Actors & malware | Security events | New attacks | TOP CVE

    python3 misp_ioc_dashboard.py --demo --out /tmp/ioc_demo.html
    python3 misp_ioc_dashboard.py --out /var/www/html/shadowatch/index.html
    python3 misp_ioc_dashboard.py --geo ...      # add country for top IPs (python3-geoip2 + .mmdb)
Requires: python3-requests. Use a read-only MISP key.
"""
import os, re, sys, json, time, random, argparse, zlib, base64
from collections import Counter
from datetime import datetime, timedelta, timezone

misp_url = os.environ.get("MISP_URL", "")
misp_key = os.environ.get("MISP_KEY", "")
misp_verifycert = os.environ.get("MISP_VERIFY_TLS", "1").lower() not in ("0", "false", "no")
EVENT_DAYS, IOC_DAYS, TOP = 90, 7, 40
GROUPS = {"ip": ("ip-dst", "ip-src"), "hash": ("sha256", "sha1", "md5"),
          "domain": ("domain", "hostname"), "url": ("url",)}
errors = []
KNOWN_MAL = ["Emotet", "QakBot", "Qbot", "Cobalt Strike", "AsyncRAT", "RedLine", "Lumma", "Raccoon", "Agent Tesla", "FormBook",
             "Remcos", "NjRAT", "DCRat", "Mirai", "IcedID", "TrickBot", "Dridex", "BazarLoader", "Pikabot", "DarkGate", "SystemBC",
             "Havoc", "Sliver", "Metasploit", "Meterpreter", "XWorm", "Vidar", "StealC", "SmokeLoader", "Gootkit", "Ursnif",
             "LockBit", "BlackCat", "Akira", "Conti", "REvil", "Ryuk", "Cl0p", "Medusa", "Rhysida", "Mallox", "GuLoader",
             "NetSupport", "Quasar", "WarZone", "SectopRAT", "Rhadamanthys", "Latrodectus", "BumbleBee", "Mozi", "Gafgyt"]
KNOWN_ACT = ["APT28", "APT29", "APT41", "APT10", "APT33", "APT34", "APT35", "APT32", "Lazarus", "Kimsuky", "Sandworm", "Turla",
             "FIN7", "FIN8", "Gamaredon", "MuddyWater", "OilRig", "Charming Kitten", "Volt Typhoon", "Salt Typhoon",
             "Scattered Spider", "TA505", "Evil Corp", "Wizard Spider", "Cozy Bear", "Fancy Bear", "Mustang Panda",
             "OceanLotus", "Andariel", "BlueNoroff"]
_MAL_RE = re.compile(r"\b(" + "|".join(map(re.escape, KNOWN_MAL)) + r")\b", re.I)
_ACT_RE = re.compile(r"\b(" + "|".join(map(re.escape, KNOWN_ACT)) + r")\b", re.I)
_CANON = {n.lower(): n for n in KNOWN_MAL + KNOWN_ACT}


def detect(rx, text, w, c):
    for m in set(x.lower() for x in rx.findall(text or "")):
        c[_CANON[m]] += w


def collect(with_geo):
    import requests
    if not misp_verifycert:
        requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    s.headers.update({"Authorization": misp_key, "Accept": "application/json", "Content-Type": "application/json"})

    def post(path, body, timeout=300):
        t0 = time.time()
        try:
            r = s.post(misp_url.rstrip("/") + path, json=body, verify=misp_verifycert, timeout=timeout)
            print(f"  {path}  {time.time() - t0:.1f}s  HTTP {r.status_code}")
            if r.status_code == 200:
                return r.json()
            errors.append(f"{path}: HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"{path}: {e}")

    since = (datetime.now(timezone.utc) - timedelta(days=EVENT_DAYS)).strftime("%Y-%m-%d")
    j = post("/events/restSearch", {"returnFormat": "json", "metadata": True, "date": since, "limit": 5000, "page": 1}) or {}
    ev = {}
    for it in j.get("response", []):
        e = it.get("Event", it)
        tags = [(t.get("Tag") or t).get("name", "") for t in (e.get("EventTag") or [])] or \
               [t.get("name", "") for t in (e.get("Tag") or [])]
        ev[str(e.get("id"))] = {"id": e.get("id"), "ts": int(e.get("timestamp") or 0), "date": e.get("date", ""),
                                "info": e.get("info", ""), "org": (e.get("Orgc") or {}).get("name", "?"),
                                "th": int(e.get("threat_level_id") or 4), "n": int(e.get("attribute_count") or 0), "tags": tags}

    types = [t for g in GROUPS.values() for t in g]
    attrs = []
    for page in range(1, 16):
        j = post("/attributes/restSearch", {"returnFormat": "json", "type": types, "to_ids": 1,
                                            "timestamp": f"{IOC_DAYS}d", "limit": 10000, "page": page}) or {}
        got = (j.get("response") or {}).get("Attribute", [])
        attrs += got
        if len(got) < 10000:
            break
    evx = {}
    miss = sorted({str(a.get("event_id")) for a in attrs} - set(ev))
    for i in range(0, len(miss), 200):
        j = post("/events/restSearch", {"returnFormat": "json", "metadata": True,
                                        "eventid": miss[i:i + 200], "limit": 200, "page": 1}) or {}
        for it in j.get("response", []):
            e = it.get("Event", it)
            evx[str(e.get("id"))] = {"id": e.get("id"), "info": e.get("info", ""),
                                     "org": (e.get("Orgc") or {}).get("name", "?")}
    return {"events": list(ev.values()), "attrs": attrs, "geo": with_geo, "evx": evx}


def demo():
    random.seed(3)
    now = int(time.time())
    orgs = ["abuse.ch", "CIRCL", "Infoblox", "CERT-EU", "Example CSIRT"]
    infos = ["ThreatFox IOCs for {d}", "MalwareBazaar malware samples for {d}", "LockBit 4.0 affiliate infrastructure",
             "APT29 phishing wave against ministries", "Emotet epoch 5 C2 update", "Cobalt Strike beacons {d}",
             "Lazarus crypto-theft campaign", "Qakbot spam run {d}"]
    actors = ["APT29", "Lazarus Group", "FIN7", "Sandworm", "Kimsuky", "Turla", "LockBit"]
    mal = ["Cobalt Strike", "Emotet", "QakBot", "AsyncRAT", "Lumma Stealer", "RedLine"]
    ev = []
    for i in range(160):
        ts = now - random.randint(0, EVENT_DAYS * 86400)
        d = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
        tg = [f'misp-galaxy:threat-actor="{random.choice(actors)}"', f'misp-galaxy:malpedia="{random.choice(mal)}"',
              f'misp-galaxy:mitre-attack-pattern="{random.choice(["Phishing - T1566", "PowerShell - T1059.001", "Valid Accounts - T1078"])}"',
              random.choice(["tlp:white", "tlp:green", "tlp:amber"])]
        ev.append({"id": 9000 + i, "ts": ts, "date": d, "info": random.choice(infos).format(d=d),
                   "org": random.choice(orgs), "th": random.choices([1, 2, 3, 4], [14, 36, 30, 20])[0],
                   "n": random.randint(5, 4000), "tags": random.sample(tg, random.randint(2, 4))})
    attrs = []
    ips = [f"{random.randint(11, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(60)]
    hs = ["%064x" % random.getrandbits(256) for _ in range(60)]
    doms = [f"{random.choice(['update', 'cdn', 'login', 'mail'])}-{random.randint(10, 99)}.{random.choice(['xyz', 'top', 'ru', 'cc'])}" for _ in range(40)]
    for i in range(3000):
        k = random.choice(["ip", "ip", "hash", "hash", "domain", "url"])
        v = random.choice({"ip": ips, "hash": hs, "domain": doms, "url": ["http://" + d + "/gate.php" for d in doms]}[k])
        t = {"ip": "ip-dst", "hash": "sha256", "domain": "domain", "url": "url"}[k]
        e = random.choice(ev)
        attrs.append({"event_id": str(e["id"]), "type": t, "value": v, "timestamp": str(now - random.randint(0, IOC_DAYS * 86400)),
                      "comment": random.choice(["", "Cobalt Strike C2", "Emotet", "QakBot", "AsyncRAT C2", "Lumma Stealer"])})
    return {"events": ev, "attrs": attrs, "geo": False, "demo": True}


COLS, ROWS, MW = 144, 56, 1000
LAND = "eNp90rFOHDEQANDxOsJJw52gQeKUvTISKa4EhNj9C5oU9wMRlCjFrQmJkgrxHfmGFJag5hfY7kSFJYhY6ZYdZsaz3Ikilrz2vfPOjscGACgWiIFGWIPUzNEtIjhP05Dk6yWQ0D/BtYbN/vzji07eQZzSWMPsOLJMsm2kBr8Qr7/t5hEs7ixY8Il6s5+fB/cXU/tAPY7WAfJKxVIPJxnAYZL2FMoK6xlAtlaIGG8gx7YiGQl0lhIdYEd7GBQahRJyNJZgNbBsC/GxBotLsWnEf3OOoxIp2l3N0oYkNcnG/QPJiU9x+IvZLUk31si8NErsTalYxYFdkvciOX9g0MnHvUhxxow4f5UBS4HPC00Q0imQIO2Qp7Sl3yWH7zo3r/W8mgNe083cVUhx4IukgKfO1CrrSYI1UQ812+O3MFozLTVQJflEOIOp3oVKqko1+Q69cIGoJqa/LiAl4x1chF5alZsfvdAvx3sqbeglJPlkdB9VLwBDr+J70VYgH+2QZp816VxkQrNZMKmKLC1LpZFZbDvl04zjJI2KwwaW0sCK0OWl2sod6IXimcjytCqcrLVRxb8mq/JxJf9MngdLGL+TYbSyZkueu/C2qQyXMvFv12zBf9sLt7YxDA=="
DEMO_GEO = [(38.9, -77, "United States", 60), (52.5, 13.4, "Germany", 30), (55.7, 37.6, "Russia", 45),
            (39.9, 116.4, "China", 50), (-23.5, -46.6, "Brazil", 15), (19, 72.9, "India", 20),
            (48.9, 2.4, "France", 18), (36.8, 10.2, "Tunisia", 5), (1.3, 103.8, "Singapore", 12)]


def land_path():
    bs = zlib.decompress(base64.b64decode(LAND))
    out = []
    for i in range(COLS * ROWS):
        if bs[i // 8] >> (7 - i % 8) & 1:
            r, c = divmod(i, COLS)
            out.append("M%.0f %.0fh0" % ((c + .5) * MW / COLS, (r + .5) * MW / COLS))
    return "".join(out)


def build(raw, geo_on):
    ev = {str(e["id"]): e for e in raw["events"]}
    ev.update(raw.get("evx") or {})
    now = int(time.time())
    gof = {t: g for g, ts in GROUPS.items() for t in ts}
    agg = {g: {} for g in GROUPS}
    hist = {g: Counter() for g in GROUPS}
    n24 = Counter()
    for a in raw["attrs"]:
        g = gof.get(a.get("type"))
        if not g:
            continue
        ts = int(a.get("timestamp") or 0)
        v = a.get("value", "")
        r = agg[g].setdefault(v, {"ev": set(), "n": 0, "last": 0, "c": "", "t": a.get("type")})
        r["ev"].add(str(a.get("event_id")))
        r["n"] += 1
        r["last"] = max(r["last"], ts)
        r["c"] = r["c"] or a.get("comment", "")
        hist[g][datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")] += 1
        if now - ts < 86400:
            n24[g] += 1

    rd = None
    if geo_on:
        try:
            import geoip2.database
            p = next((x for x in [os.environ.get("GEOIP_DB", ""), "/usr/share/GeoIP/GeoLite2-City.mmdb", "/opt/GeoLite2-City.mmdb",
                                  "/opt/dbip-city-lite.mmdb", "/opt/GeoLite2-Country.mmdb"] if x and os.path.exists(x)), None)
            rd = geoip2.database.Reader(p) if p else None
            if not rd:
                errors.append("geo: no .mmdb database found (set GEOIP_DB)")
        except ImportError:
            errors.append("geo: apt install python3-geoip2")

    gcell, gcc = Counter(), Counter()
    if rd:
        for v in agg["ip"]:
            try:
                x = rd.city(v)
                if x.location.latitude is None:
                    continue
                gcell[(round(x.location.latitude / 3.0), round(x.location.longitude / 3.0))] += 1
                gcc[x.country.name or "Unknown"] += 1
            except Exception:
                pass
    elif raw.get("demo"):
        for la, lo, nm, n in DEMO_GEO:
            gcell[(round(la / 3.0), round(lo / 3.0))] += n
            gcc[nm] += n
    top = {}
    for g, m in agg.items():
        rows = []
        for v, r in sorted(m.items(), key=lambda kv: (-len(kv[1]["ev"]), -kv[1]["n"]))[:TOP]:
            e0 = ev.get(sorted(r["ev"])[0], {})
            cc = ""
            if rd and g == "ip":
                try:
                    x = rd.city(v) if hasattr(rd, "city") else rd.country(v)
                    cc = x.country.name or ""
                except Exception:
                    pass
            rows.append([v, r["t"], len(r["ev"]), r["n"], r["last"], e0.get("org", "?"), e0.get("info", "")[:70], r["c"][:40], cc])
        top[g] = rows

    typ, src, cm, newest = Counter(), Counter(), Counter(), 0
    for g, m in agg.items():
        for v, r in m.items():
            typ[r["t"]] += 1
            newest = max(newest, r["last"])
            src[ev.get(next(iter(r["ev"])), {}).get("org", "?")] += 1
            if r["c"].strip():
                cm[r["c"].strip()[:40]] += 1
    mal_h, act_h = Counter(), Counter()
    for e in raw["events"]:
        detect(_MAL_RE, e["info"], 1, mal_h)
        detect(_ACT_RE, e["info"], 1, act_h)
    for text, w in cm.items():
        detect(_MAL_RE, text, w, mal_h)
        detect(_ACT_RE, text, w, act_h)
    cut = now - EVENT_DAYS * 86400
    evs = [e for e in raw["events"] if e["ts"] >= cut or True]
    cnt = {k: Counter() for k in ("actor", "malware", "tech", "tag")}
    for e in evs:
        for t in e["tags"]:
            m = re.match(r'misp-galaxy:([\w-]+)="(.+)"$', t)
            if m:
                gal, val = m.groups()
                key = {"threat-actor": "actor", "mitre-intrusion-set": "actor", "malpedia": "malware", "mitre-malware": "malware",
                       "ransomware": "malware", "mitre-attack-pattern": "tech"}.get(gal)
                if key:
                    cnt[key][val] += 1
            elif not t.startswith(("tlp:", "workflow:")) and t:
                cnt["tag"][t] += 1
    days = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(IOC_DAYS - 1, -1, -1)]
    sec = sorted([e for e in evs if e["th"] <= 2], key=lambda e: (e["th"], -e["n"], -e["ts"]))[:40]
    new = sorted(evs, key=lambda e: -e["ts"])[:30]
    actors, malware = cnt["actor"].most_common(12), cnt["malware"].most_common(12)
    nact = nmal = ""
    if not actors and act_h:
        actors, nact = act_h.most_common(12), "detected in event titles and IOC comments (no galaxy tags)"
    if not malware and mal_h:
        malware, nmal = mal_h.most_common(12), "detected in event titles and IOC comments (no galaxy tags)"
    return {"gen": datetime.now().strftime("%Y-%m-%d %H:%M"), "genTs": now, "newest": newest,
            "typ": typ.most_common(10), "src": src.most_common(8), "ctx": cm.most_common(10), "nact": nact, "nmal": nmal, "demo": bool(raw.get("demo")), "errors": errors[:4],
            "kpi": {"events": len(evs), "iocs": sum(len(m) for m in agg.values()), "n24": sum(n24.values()),
                    "high": sum(1 for e in evs if e["th"] == 1), "orgs": len({e["org"] for e in evs})},
            "days": days, "hist": [[hist[g][d] for d in days] for g in GROUPS], "grp": list(GROUPS), "top": top,
            "actors": actors, "malware": malware,
            "tech": cnt["tech"].most_common(12), "tags": cnt["tag"].most_common(12),
            "th": [sum(1 for e in evs if e["th"] == k) for k in (1, 2, 3, 4)],
            "orgs": Counter(e["org"] for e in evs).most_common(6), "sec": sec, "new": new,
            "gpts": [[k[0] * 3, k[1] * 3, n] for k, n in gcell.items()],
            "gcc": gcc.most_common(10), "land": land_path()}


TEMPLATE = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="600"><title>ShadoWATCH | Threat Intelligence</title><style>
:root{--bg:#0a0f1c;--p:#111a2e;--p2:#17233d;--t:#e8eefb;--m:#8593b0;--l:#223156;--a:#4f8cff;--r:#ef476f;--o:#ffb703;--g:#06d6a0;--v:#9b5de5}
@media(prefers-color-scheme:light){:root{--bg:#f1f4fa;--p:#fff;--p2:#eef2fa;--t:#15203a;--m:#5b6988;--l:#dbe3f2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:14px system-ui,Segoe UI,Roboto,Arial,sans-serif}
header{display:flex;align-items:center;gap:18px;padding:14px 24px;border-bottom:1px solid var(--l);flex-wrap:wrap}
h1{font-size:18px;margin:0}h1 b{color:var(--a)}.live{color:var(--g);font-size:12px}.live:before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--g);margin-right:6px;animation:b 1.6s infinite}
@keyframes b{50%{opacity:.25}}nav{display:flex;gap:6px;margin-left:auto;flex-wrap:wrap}
nav button{background:var(--p);color:var(--m);border:1px solid var(--l);padding:7px 14px;border-radius:8px;cursor:pointer;font-size:13px}
nav button.on{background:var(--a);color:#fff;border-color:var(--a)}main{padding:18px 24px;max-width:1500px;margin:auto}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:14px}
.kp{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:14px 16px;border-top:3px solid var(--a)}
.kp small{color:var(--m);text-transform:uppercase;letter-spacing:.6px;font-size:11px}.kp div{font-size:27px;font-weight:700;margin-top:4px}
.g{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.c{background:var(--p);border:1px solid var(--l);border-radius:12px;padding:16px;min-width:0}
.c h2{margin:0 0 12px;font-size:12px;color:var(--m);text-transform:uppercase;letter-spacing:.7px}.s4{grid-column:span 4}.s6{grid-column:span 6}.s8{grid-column:span 8}.s12{grid-column:span 12}
@media(max-width:1000px){.s4,.s6,.s8{grid-column:span 12}}.pane{display:none}.pane.on{display:block}
input{background:var(--p2);color:var(--t);border:1px solid var(--l);border-radius:8px;padding:7px 12px;width:260px}
table{width:100%;border-collapse:collapse;font-size:12.5px}th{text-align:left;color:var(--m);padding:6px 8px;border-bottom:1px solid var(--l);font-size:11.5px;position:sticky;top:0;background:var(--p)}
td{padding:6px 8px;border-bottom:1px solid var(--l);max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}tr:hover td{background:var(--p2)}
.mono{font-family:Consolas,Menlo,monospace;cursor:copy}.bd{color:#111;font-weight:700;font-size:11px;padding:2px 8px;border-radius:99px}
.br{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:12.5px}.br span:first-child{width:46%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.br i{display:block;height:14px;border-radius:4px;opacity:.9}.br em{color:var(--m);font-style:normal}.sc{max-height:520px;overflow:auto}
.tl{border-left:2px solid var(--l);margin-left:6px;padding-left:16px}.tl div{position:relative;padding:8px 0;border-bottom:1px dashed var(--l)}
.tl div:before{content:"";position:absolute;left:-23px;top:14px;width:10px;height:10px;border-radius:50%;background:var(--a)}
.tag{display:inline-block;background:var(--p2);border:1px solid var(--l);border-radius:6px;padding:1px 7px;margin:2px 3px 0 0;font-size:11px;color:var(--m)}
.bn{background:var(--p2);border:1px dashed var(--o);color:var(--o);padding:8px 14px;border-radius:8px;margin-bottom:12px;font-size:13px}
.toast{position:fixed;bottom:20px;right:20px;background:var(--g);color:#052;padding:8px 16px;border-radius:8px;display:none}
</style></head><body>
<header><h1><b>ShadoWATCH</b> Threat Intelligence</h1><span class="live">updated <span id="gen"></span></span>
<nav id="nav"></nav></header><main><div id="bn"></div><div class="k" id="kpi"></div>
<div class="pane on" id="p0"><div class="g">
<div class="c s8"><h2>IOC ingestion, last 7 days (by type)</h2><div id="ing"></div></div>
<div class="c s4"><h2>Events by threat level</h2><div id="thr"></div><h2 style="margin-top:16px">Contributing organisations</h2><div id="org"></div></div>
<div class="c s8"><h2>IP sources map</h2><div id="mp"></div></div><div class="c s4"><h2>Top source countries</h2><div id="mc"></div></div><div class="c s4"><h2>Top IPs</h2><div id="mi"></div></div><div class="c s4"><h2>Top hashes</h2><div id="mh"></div></div>
<div class="c s4"><h2>Top threat actors</h2><div id="ma"></div></div>
<div class="c s4"><h2>IOC types (unique, 7 d)</h2><div id="ty"></div></div><div class="c s4"><h2>IOCs by source</h2><div id="sr"></div></div>
<div class="c s4"><h2>Malware / context (from IOC comments)</h2><div id="cx"></div></div></div></div>
<div class="pane" id="p1"><p><input id="q" placeholder="Filter IOCs (IP, hash, domain, org, malware)..."> <span class="tag">click a value to copy it</span></p>
<div class="g"><div class="c s12"><h2>Top IP addresses</h2><div class="sc" id="t0"></div></div>
<div class="c s12"><h2>Top file hashes</h2><div class="sc" id="t1"></div></div>
<div class="c s6"><h2>Top domains</h2><div class="sc" id="t2"></div></div><div class="c s6"><h2>Top URLs</h2><div class="sc" id="t3"></div></div></div></div>
<div class="pane" id="p2"><div class="g"><div class="c s6"><h2>Threat actors</h2><div id="a1"></div></div><div class="c s6"><h2>Malware families</h2><div id="a2"></div></div>
<div class="c s6"><h2>MITRE ATT&amp;CK techniques</h2><div id="a3"></div></div><div class="c s6"><h2>Other tags</h2><div id="a4"></div></div></div></div>
<div class="pane" id="p3"><div class="c"><h2>Security events (High and Medium threat, ranked by severity then size)</h2><div class="sc" id="se"></div></div></div>
<div class="pane" id="p4"><div class="c"><h2>New attacks, latest events first</h2><div class="tl" id="nw"></div></div></div><div class="pane" id="p5"><div id="cb5"></div><div class="g"><div class="c s4"><h2>CVE severity (30 d)</h2><div id="v1"></div></div><div class="c s8"><h2>Newest vulnerabilities (OpenCTI)</h2><div class="sc" id="v2"></div></div></div></div>
<div class="pane" id="p6"><div id="cb6"></div><div class="g"><div class="c s4"><h2>Most targeted sectors</h2><div id="r1"></div></div><div class="c s4"><h2>Top attack techniques</h2><div id="r2"></div></div><div class="c s4"><h2>Top malware used</h2><div id="r3"></div></div><div class="c s4"><h2>Most targeted countries</h2><div id="r5"></div></div><div class="c s8"><h2>Recently updated threat actors</h2><div id="r6"></div></div><div class="c s12"><h2>Latest intelligence reports</h2><div class="sc" id="r4"></div></div></div></div>
</main><div class="toast" id="ts">copied</div>
<script>
var D=__DATA__,TH=[['High','#ef476f'],['Medium','#ffb703'],['Low','#06d6a0'],['Undef.','#8d99ae']],GC=['#4f8cff','#9b5de5','#06d6a0','#ffb703'],GN=['IP','Hash','Domain','URL'];
function $(i){return document.getElementById(i)}function E(s){return String(s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function df(v,t){return t=='url'?v.replace(/^http/,'hxxp').replace(/\./g,'[.]'):(t=='domain'||t=='hostname'||/^\d+\.\d+\.\d+\.\d+$/.test(v))?v.replace(/\./g,'[.]'):v}
function dt(t){return t?new Date(t*1e3).toISOString().slice(0,16).replace('T',' '):''}
function ago(t){var s=Date.now()/1e3-t;return s<3600?Math.max(1,s/60|0)+' min ago':s<86400?(s/3600|0)+' h ago':(s/86400|0)+' d ago'}
function bars(el,it,c){var m=Math.max.apply(null,it.map(function(x){return x[1]}).concat([1]));$(el).innerHTML=it.length?it.map(function(x){return'<div class="br"><span title="'+E(x[0])+'">'+E(x[0])+'</span><i style="width:'+(46*x[1]/m)+'%;background:'+c+'"></i><em>'+x[1]+'</em></div>'}).join(''):'<span class="tag">no data yet: needs galaxy-tagged events (enable the CIRCL OSINT feed)</span>'}
function badge(t){return'<span class="bd" style="background:'+TH[t-1][1]+'">'+TH[t-1][0]+'</span>'}
var tabs=['Overview','IOCs','Actors & malware','Security events','New attacks','Vulnerabilities','Intel reports'];
$('nav').innerHTML=tabs.map(function(t,i){return'<button data-i="'+i+'"'+(i?'':' class="on"')+'>'+t+'</button>'}).join('');
document.querySelectorAll('nav button').forEach(function(b){b.onclick=function(){document.querySelectorAll('nav button').forEach(function(x){x.className=''});b.className='on';for(var i=0;i<7;i++)$('p'+i).className='pane'+(i==b.dataset.i?' on':'')}});
$('gen').textContent=D.gen;
var nowS=Date.now()/1e3,B=[];if(D.demo)B.push('DEMO DATA');D.errors.forEach(function(x){B.push(x)});
if(!D.newest||nowS-D.newest>172800)B.push('NO NEW IOC since '+(D.newest?dt(D.newest):'the whole window')+'. Check MISP feed fetching.');
if(nowS-D.genTs>10800)B.push('Page generated '+ago(D.genTs)+'. The refresh job may have stopped.');
$('bn').innerHTML=B.map(function(x){return'<div class="bn">'+E(x)+'</div>'}).join('');
var fr=D.newest?nowS-D.newest:1e9,FC=fr<21600?'#06d6a0':fr<172800?'#ffb703':'#ef476f';
var K=[['Newest IOC',D.newest?ago(D.newest):'none',FC],['Events (90 d)',D.kpi.events,'#4f8cff'],['Unique IOCs (7 d)',D.kpi.iocs,'#9b5de5'],['New IOCs (24 h)',D.kpi.n24,'#06d6a0'],['High-threat events',D.kpi.high,'#ef476f'],['Organisations',D.kpi.orgs,'#ffb703']];
$('kpi').innerHTML=K.map(function(k){return'<div class="kp" style="border-top-color:'+k[2]+'"><small>'+k[0]+'</small><div'+(typeof k[1]=='number'?' data-n="'+k[1]+'">0':'>'+E(k[1]))+'</div></div>'}).join('');
document.querySelectorAll('[data-n]').forEach(function(e){var n=+e.dataset.n,v=0,s=Math.max(1,Math.ceil(n/35)),i=setInterval(function(){v=Math.min(n,v+s);e.textContent=v.toLocaleString('fr-FR');if(v>=n)clearInterval(i)},25)});
(function(){var n=D.days.length,W=760,H=240,L=44,B=26,T=10,mx=1,i,j,h='';for(i=0;i<n;i++){var t=0;for(j=0;j<4;j++)t+=D.hist[j][i];mx=Math.max(mx,t)}
var bw=(W-L-8)/n;for(var g=0;g<4;g++){var y=T+(H-T-B)*g/3;h+='<line x1="'+L+'" x2="'+(W-8)+'" y1="'+y+'" y2="'+y+'" stroke="var(--l)"/><text x="'+(L-6)+'" y="'+(y+4)+'" text-anchor="end" fill="var(--m)" font-size="11">'+Math.round(mx*(1-g/3))+'</text>'}
for(i=0;i<n;i++){var y0=H-B,x=L+i*bw+bw*.18;for(j=0;j<4;j++){var v=D.hist[j][i];if(!v)continue;var hh=(H-T-B)*v/mx;y0-=hh;h+='<rect x="'+x+'" y="'+y0+'" width="'+bw*.64+'" height="'+hh+'" fill="'+GC[j]+'" rx="3"><title>'+D.days[i]+' '+GN[j]+': '+v+'</title></rect>'}h+='<text x="'+(x+bw*.32)+'" y="'+(H-8)+'" text-anchor="middle" fill="var(--m)" font-size="11">'+D.days[i].slice(5)+'</text>'}
$('ing').innerHTML='<svg viewBox="0 0 '+W+' '+H+'" width="100%">'+h+'</svg>'+GN.map(function(x,k){return'<span class="tag"><b style="color:'+GC[k]+'">&#9632;</b> '+x+'</span>'}).join('')})();
bars('thr',D.th.map(function(v,i){return[TH[i][0],v]}),'#ef476f');bars('org',D.orgs,'#2ec4b6');
bars('mi',D.top.ip.slice(0,8).map(function(r){return[df(r[0],'ip'),r[2]]}),'#4f8cff');bars('mh',D.top.hash.slice(0,8).map(function(r){return[r[0].slice(0,20)+'...',r[2]]}),'#9b5de5');
bars('ma',D.actors.slice(0,8),'#ef476f');bars('ty',D.typ,'#4f8cff');bars('sr',D.src,'#2ec4b6');bars('cx',D.ctx,'#ffb703');bars('a1',D.actors,'#ef476f');bars('a2',D.malware,'#ffb703');bars('a3',D.tech,'#9b5de5');bars('a4',D.tags,'#4f8cff');
[['ma',D.nact],['a1',D.nact],['a2',D.nmal]].forEach(function(x){if(x[1])$(x[0]).insertAdjacentHTML('beforeend','<span class="tag">'+E(x[1])+'</span>')});
function go(i,q){document.querySelectorAll('nav button')[i].click();$('q').value=q;$('q').oninput()}
(function(){var W=1000,H=W*140/360,P=D.gpts||[],mx=1,h='<svg viewBox="0 0 '+W+' '+H.toFixed(0)+'" width="100%"><path d="'+(D.land||'')+'" fill="none" stroke="var(--l)" stroke-width="4.2" stroke-linecap="round"/>';
P.forEach(function(p){mx=Math.max(mx,p[2])});
P.forEach(function(p){var x=((p[1]+180)/360*W).toFixed(0),y=((82-Math.max(-58,Math.min(82,p[0])))/140*H).toFixed(0),r=4+Math.sqrt(p[2]/mx)*20;
h+='<circle cx="'+x+'" cy="'+y+'" r="'+r.toFixed(1)+'" fill="#ef476f" fill-opacity=".22"/><circle cx="'+x+'" cy="'+y+'" r="'+Math.max(2.5,r*.4).toFixed(1)+'" fill="#ef476f"><title>'+p[2]+' IPs</title></circle>'});
$('mp').innerHTML=P.length?h+'</svg>':'<span class="tag">Map needs GeoIP: run with --geo and a .mmdb file</span>';
bars('mc',D.gcc||[],'#118ab2');
['mc','ty','sr','cx','ma','a1','a2'].forEach(function(id){document.querySelectorAll('#'+id+' .br').forEach(function(r){r.style.cursor='pointer';r.title='click to filter the IOC table';r.onclick=function(){go(1,r.firstChild.textContent.toLowerCase())}})});
var au=document.createElement('button'),T0=null,ti=0;au.textContent='\u25B6 Presentation';
au.style.cssText='background:var(--p);color:var(--g);border:1px solid var(--g);padding:7px 14px;border-radius:8px;cursor:pointer';
$('nav').parentNode.insertBefore(au,$('nav'));
au.onclick=function(){if(T0){clearInterval(T0);T0=null;au.textContent='\u25B6 Presentation';return}
au.textContent='\u25A0 Stop';var f=function(){var b=document.querySelectorAll('nav button');ti=(ti+1)%b.length;b[ti].click()};f();T0=setInterval(f,20000)}})();
function tbl(id,g,hasGeo){var r=D.top[g];$(id).innerHTML='<table><tr><th>IOC</th><th>Events</th><th>Seen</th><th>Last seen</th><th>Source</th><th>Context</th>'+(hasGeo?'<th>Country</th>':'')+'</tr>'+r.map(function(x){return'<tr data-s="'+E((x.join(' ')).toLowerCase())+'"><td class="mono" data-v="'+E(x[0])+'" title="'+E(x[0])+'">'+E(df(x[0],x[1]))+'</td><td>'+x[2]+'</td><td>'+x[3]+'</td><td>'+ago(x[4])+'</td><td>'+E(x[5])+'</td><td title="'+E(x[6])+'">'+E(x[7]||x[6])+'</td>'+(hasGeo?'<td>'+E(x[8])+'</td>':'')+'</tr>'}).join('')+'</table>'}
tbl('t0','ip',D.top.ip.some(function(x){return x[8]}));tbl('t1','hash');tbl('t2','domain');tbl('t3','url');
document.addEventListener('click',function(e){var v=e.target.dataset&&e.target.dataset.v;if(v){var f=function(){$('ts').style.display='block';setTimeout(function(){$('ts').style.display='none'},1200)};navigator.clipboard?navigator.clipboard.writeText(v).then(f):f()}});
$('q').oninput=function(){var q=this.value.toLowerCase();document.querySelectorAll('tr[data-s]').forEach(function(r){r.style.display=r.dataset.s.indexOf(q)<0?'none':''})};
function tg(t){return t.filter(function(x){return!/^(tlp|workflow):/.test(x)}).slice(0,4).map(function(x){return'<span class="tag">'+E(x.replace(/misp-galaxy:/,'').slice(0,46))+'</span>'}).join('')}
$('se').innerHTML='<table><tr><th>Severity</th><th>Event</th><th>Date</th><th>Org</th><th>IOCs</th><th>Tags</th></tr>'+D.sec.map(function(e){return'<tr><td>'+badge(e.th)+'</td><td title="'+E(e.info)+'">#'+e.id+' '+E(e.info.slice(0,70))+'</td><td>'+E(e.date)+'</td><td>'+E(e.org)+'</td><td>'+e.n+'</td><td style="white-space:normal">'+tg(e.tags)+'</td></tr>'}).join('')+'</table>';
$('nw').innerHTML=D.new.map(function(e){return'<div>'+badge(e.th)+' <b>#'+e.id+'</b> '+E(e.info)+' <span class="tag">'+E(e.org)+'</span> <span class="tag">'+e.n+' IOCs</span> <span class="tag">'+ago(e.ts)+'</span><br>'+tg(e.tags)+'</div>'}).join('');
fetch('cti.json?'+Date.now()).then(function(r){return r.json()}).then(function(C){
var SC={critical:'#ef476f',high:'#f78c6b',medium:'#ffb703',low:'#06d6a0'},KC={act:'#ef476f',mal:'#ffb703',tech:'#9b5de5',sec:'#2ec4b6',cve:'#4f8cff',lab:'#8593b0'};
function ch(a,k){return(a||[]).map(function(x){return'<span class="tag" style="border-color:'+KC[k]+'">'+E(x)+'</span>'}).join('')}
var bad=(C.diag||[]).filter(function(x){return x.indexOf('ERROR')>0}),nb=(C.stale?'<div class="bn">OpenCTI unreachable: showing cached data from '+dt(C.ts)+'</div>':'')+(bad.length?'<div class="bn">Some OpenCTI sections failed: '+E(bad.slice(0,3).join(' | '))+'</div>':'');
$('cb5').innerHTML=nb;$('cb6').innerHTML=nb;
var cv=C.cves||[],sv={};cv.forEach(function(v){var k=(v.sev||'unrated').toLowerCase();sv[k]=(sv[k]||0)+1});
bars('v1',Object.keys(sv).map(function(k){return[k,sv[k]]}),'#ef476f');
$('v2').innerHTML=cv.length?'<table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Date</th><th>Description</th></tr>'+cv.map(function(v){var k=(v.sev||'').toLowerCase();return'<tr><td class="mono" data-v="'+E(v.n)+'">'+E(v.n)+'</td><td>'+(k?'<span class="bd" style="background:'+(SC[k]||'#8d99ae')+'">'+E(v.sev)+'</span>':'n/a')+'</td><td>'+(v.s==null?'n/a':v.s)+'</td><td>'+(v.e==null?'':(v.e*100).toFixed(1)+'%')+'</td><td>'+(v.k?'<b style="color:#ef476f">KEV</b>':'')+'</td><td>'+E((v.t||'').slice(0,10))+'</td><td title="'+E(v.d)+'">'+E(v.d.slice(0,90))+'</td></tr>'}).join('')+'</table>':'<span class="tag">no CVE data (check the OpenCTI connectors)</span>';
bars('r1',C.sectors||[],'#2ec4b6');bars('r2',C.tech||[],'#9b5de5');bars('r3',C.mal||[],'#ffb703');bars('r5',C.countries||[],'#118ab2');
$('r6').innerHTML=(C.actors||[]).map(function(a){return'<span class="tag" title="'+E(a[1].slice(0,10))+'" style="border-color:'+KC.act+'">'+E(a[0])+'</span>'}).join('')||'<span class="tag">no data</span>';
$('r4').innerHTML=(C.reports||[]).length?'<table><tr><th>Date</th><th>Report</th><th>Source</th><th>Attack type / context</th></tr>'+C.reports.map(function(r){var t=r.url?'<a href="'+E(r.url)+'" target="_blank" rel="noopener" style="color:var(--a)">'+E(r.n.slice(0,80))+'</a>':E(r.n.slice(0,80));return'<tr><td>'+E(r.t.slice(0,10))+'</td><td style="white-space:normal;max-width:380px" title="'+E(r.d)+'">'+t+'</td><td>'+E(r.src)+'</td><td style="white-space:normal">'+ch(r.lab,'lab')+ch(r.act,'act')+ch(r.mal,'mal')+ch(r.tech,'tech')+ch(r.sec,'sec')+ch(r.cve,'cve')+'</td></tr>'}).join('')+'</table>':'<span class="tag">no reports yet</span>';
}).catch(function(){['v2','r4'].forEach(function(i){$(i).innerHTML='<span class="tag">cti.json not available yet (run the OpenCTI fetcher)</span>'})});
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="misp_ioc_dashboard.html")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--geo", action="store_true", help="country for top IPs (python3-geoip2 + .mmdb)")
    a = ap.parse_args()
    if not a.demo and not (misp_url and misp_key):
        sys.exit("Set MISP_URL and MISP_KEY (see .env.example).")
    raw = demo() if a.demo else collect(a.geo)
    data = build(raw, a.geo and not a.demo)
    page = TEMPLATE.replace("__DATA__", json.dumps(data).replace("</", "<\\/"))
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out + ".tmp", "w", encoding="utf-8") as f:
        f.write(page)
    os.replace(a.out + ".tmp", a.out)
    print(f"Dashboard written to {a.out} ({len(page) // 1024} KB)")
    for e in errors:
        print("  warning:", e)


if __name__ == "__main__":
    main()
