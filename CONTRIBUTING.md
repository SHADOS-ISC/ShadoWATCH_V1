# Contributing

Issues and pull requests are welcome.

1. Open an issue first for larger changes.
2. Keep the project dependency-light (Python standard library + `requests`) and the page self-contained (no CDN).
3. Run the checks before opening a PR:
   ```bash
   python3 -m py_compile misp_ioc_dashboard.py misp_cti.py
   python3 -m unittest discover -s tests -v
   python3 misp_ioc_dashboard.py --demo --out /tmp/demo.html
   ```
4. Never include real IOCs, keys, hostnames or screenshots of real data. Use `--demo` for screenshots.
