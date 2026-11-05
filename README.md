# ShadoWATCH

**Threat-intelligence dashboard for Security Operations Centers.**
Turns the IOCs in your **MISP** instance and the context in your **OpenCTI** platform into a
live, wall-screen-ready view for SOC analysts.

![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)
![Status](https://img.shields.io/badge/status-active-00D9FF?style=flat-square)

> Built from a real SOC need: analysts should see what is new, what is dangerous and what is
> stale **without** opening five consoles. If the data stops flowing, the screen says so.

![Overview](docs/screenshots/01-overview.png)

<details><summary>More screenshots (all generated from fake demo data)</summary>

| IOCs | Actors & malware | Security events |
|---|---|---|
| ![IOCs](docs/screenshots/02-iocs.png) | ![Actors](docs/screenshots/03-actors-malware.png) | ![Events](docs/screenshots/04-security-events.png) |

| New attacks | Vulnerabilities | Intel reports |
|---|---|---|
| ![New](docs/screenshots/05-new-attacks.png) | ![Vulns](docs/screenshots/06-vulnerabilities.png) | ![Reports](docs/screenshots/07-intel-reports.png) |

</details>

Try it without any MISP or OpenCTI: `python3 misp_ioc_dashboard.py --demo --out demo.html`

## What it shows

| Tab | Content |
|---|---|
| **Overview** | Freshness of the newest IOC, ingestion trend, threat levels, top IPs and hashes, source-country map, IOC types and sources |
| **IOCs** | Top IPs, file hashes, domains and URLs with source, context and last-seen. Search box, click to copy |
| **Actors & malware** | Actors, malware families, MITRE ATT&CK techniques and tags from MISP galaxies (with a clearly labelled fallback based on event titles and IOC comments) |
| **Security events** | High and medium threat events ranked by severity and size |
| **New attacks** | Timeline of the latest events |
| **Vulnerabilities** | Newest CVEs from OpenCTI with EPSS and CISA KEV flags |
| **Intel reports** | Latest reports with related actors, malware, techniques and sectors, plus most-targeted sectors and countries |

**Built for operations**
- **Stale-data warnings:** a banner appears if no new IOC arrived for 48 h or if the page itself stopped refreshing.
- **Wall mode:** the *Presentation* button rotates the tabs every 20 seconds for SOC screens.
- **Resilient:** if OpenCTI is unreachable, the page keeps the last copy and says so.
- **Self-contained:** one HTML file, no CDN, works on an isolated network.

## Architecture

```
 MISP  --REST-->  misp_ioc_dashboard.py --\
                                           >--> misp-ioc.html  --> web server --> SOC screens
 OpenCTI --GraphQL--> misp_cti.py ---------/   (+ cti.json)
                         ^
                         |  cron every 30 min (flock prevents overlap)
```

## Requirements
- MISP 2.5.x with a read-only API key (tested on 2.5.34)
- OpenCTI 6.x with a read-only token (tested on 6.3.6), optional
- Python 3.8+ and `python3-requests`
- Optional: `python3-geoip2` and a GeoIP city database (`.mmdb`) for the map

## Quick start

```bash
git clone https://github.com/SHADOS-ISC/ShadoWATCH.git
cd ShadoWATCH
sudo apt install -y python3-requests python3-geoip2

# 1. configuration (keep the file private)
sudo cp .env.example /etc/shadowatch.env && sudo chmod 600 /etc/shadowatch.env
sudoedit /etc/shadowatch.env

# 2. generate the page once
set -a; . /etc/shadowatch.env; set +a
sudo mkdir -p /var/www/html/shadowatch
export CTI_OUT=/var/www/html/shadowatch/cti.json   # must sit next to index.html
python3 misp_cti.py
python3 misp_ioc_dashboard.py --geo --out /var/www/html/shadowatch/index.html
```

Schedule it (every 30 minutes, never two runs at once):

```
*/30 * * * * flock -n /tmp/shadowatch.lock /opt/ShadoWATCH/deploy/run.sh >/var/log/shadowatch.log 2>&1
```

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `MISP_URL`, `MISP_KEY` | yes | MISP address and read-only API key |
| `MISP_VERIFY_TLS` | no | `1` (default) verifies the certificate; `0` only for lab setups |
| `OPENCTI_URL`, `OPENCTI_TOKEN` | no | Enables the Vulnerabilities and Intel reports tabs |
| `GEOIP_DB` | no | Path of a GeoIP city `.mmdb` file for the map |
| `OPENCTI_VERIFY_TLS` | no | `1` (default) verifies the certificate; `0` only for lab setups |
| `CTI_OUT` | no | Output path of the OpenCTI JSON file (default `cti.json`; keep it next to the page) |

## Hardening checklist
See [SECURITY.md](SECURITY.md). In short: read-only keys, a private env file, access restricted to
the SOC network, TLS in production.

## Known limitations
- Actor and malware cards fall back to name detection in event titles and IOC comments when events carry no galaxy tags. They are labelled as such.
- Volume-heavy blocklists (for example IPsum or scanner lists) dominate raw IOC counts. Consider enabling only feeds you trust.
- The OpenCTI queries target the 6.x GraphQL schema. Each section fails independently and is reported on the page.

## Roadmap
- [x] Smoke tests and CI (GitHub Actions)
- [ ] Configurable feed allow-list (qualified intelligence vs. bulk blocklists)
- [ ] Packaging (`pip install`) and a container image

## License
Apache-2.0. See [LICENSE](LICENSE).

## Disclaimer
ShadoWATCH is an independent project. It is not affiliated with, endorsed by or sponsored by the MISP
Project, Filigran (OpenCTI), IBM or MaxMind. Product names are trademarks of their owners.
The GeoIP database is **not** included: obtain it under its own licence.

## Author
Islem Cherif · [SHADOS-ISC](https://github.com/SHADOS-ISC) · SOC engineering and threat-intelligence automation
