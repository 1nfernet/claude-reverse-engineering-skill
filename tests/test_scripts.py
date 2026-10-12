#!/usr/bin/env python3
"""Dependency-free test + structure validator for the reverse-engineering skill.

Runs with plain `python tests/test_scripts.py` (no pytest, no third-party deps)
so it works in any CI runner. Exercises the three runnable scripts on synthesized
fixtures and validates the skill's structure and manifests.

Exit code 0 = all passed, 1 = something failed.
"""
from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(ROOT, "skills", "reverse-engineering")
SCRIPTS = os.path.join(SKILL, "scripts")
PY = sys.executable

_failures = []
_passed = 0


def check(name, cond, detail=""):
    global _passed
    if cond:
        _passed += 1
        print("  ok   " + name)
    else:
        _failures.append(name + ((" — " + detail) if detail else ""))
        print("  FAIL " + name + ((" — " + detail) if detail else ""))


def run(args, **kw):
    """Run a bundled script with -I (isolated) and return (rc, stdout+stderr)."""
    p = subprocess.run([PY, "-I"] + args, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout + p.stderr


# ---------------------------------------------------------------------------
# 1. Every bundled .py compiles (covers the PyGhidra/Jython Ghidra script too, which
#    is written to also be valid CPython 3).
# ---------------------------------------------------------------------------
def test_compile():
    print("\n[compile] all bundled scripts byte-compile under this Python")
    import py_compile
    for dirpath, _dirs, files in os.walk(SCRIPTS):
        for fn in files:
            if fn.endswith(".py"):
                path = os.path.join(dirpath, fn)
                try:
                    py_compile.compile(path, doraise=True)
                    check("compile " + os.path.relpath(path, SKILL), True)
                except py_compile.PyCompileError as e:
                    check("compile " + os.path.relpath(path, SKILL), False, str(e))


# ---------------------------------------------------------------------------
# 2. triage.py: detection, routing, and regressions for audited flaws.
# ---------------------------------------------------------------------------
def make_pe(clr=False, extra=b""):
    """Minimal valid PE32+ with one section; optionally a CLR (.NET) data directory."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 1, 0x60000000, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 108, 16)
    if clr:
        struct.pack_into("<II", opt, 112 + 14 * 8, 0x2000, 0x48)
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIII", sec, 8, 0x1000, 0x1000, 0x200, 0x200)
    body = bytes(dos) + coff + bytes(opt) + bytes(sec)
    return body + b"\x00" * (0x200 - len(body)) + b"\x90" * 0x200 + extra


def tri(triage, path, *extra):
    rc, out = run([triage, path, "--json", "--no-strings"] + list(extra))
    try:
        return rc, json.loads(out)
    except ValueError:
        return rc, {"_raw": out[:300]}


def fp_names(data):
    return [f["name"] for f in data.get("fingerprints", [])]


def test_triage():
    print("\n[triage] detection, routing, regressions")
    triage = os.path.join(SCRIPTS, "triage.py")
    with tempfile.TemporaryDirectory() as d:
        def write(name, blob):
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(blob)
            return p

        elf = write("a.out", b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 3, 183) + b"\x00" * 100)
        rc, data = tri(triage, elf)
        check("ELF -> native-elf", rc == 0 and data.get("route_key") == "native-elf", data.get("route_key"))
        check("ELF arch parsed (AArch64)", data.get("format_details", {}).get("arch") == "AArch64")
        rc, out = run([triage, elf, "--json"])
        check("emits sha256", len(json.loads(out).get("hashes", {}).get("sha256", "")) == 64)

        rc, data = tri(triage, write("native.exe", make_pe()))
        check("PE -> native-pe, x86-64", data.get("route_key") == "native-pe"
              and data.get("format_details", {}).get("arch") == "x86-64", str(data.get("format_details")))
        rc, data = tri(triage, write("managed.dll", make_pe(clr=True)))
        check(".NET detected from CLR header", data.get("route_key") == "dotnet", data.get("route_key"))
        # regression: a non-Electron PE that merely contains "node_modules"/"electron" strings
        rc, data = tri(triage, write("node.exe", make_pe(extra=b"node_modules electron chrome-devtools")))
        check("no false Electron on plain PE", "Electron app" not in fp_names(data), str(fp_names(data)))
        rc, data = tri(triage, write("app.exe", make_pe(extra=b"ELECTRON_RUN_AS_NODE")))
        check("Electron detected from real marker", "Electron app" in fp_names(data), str(fp_names(data)))
        # regression: markers beyond the analysis window must still be found (whole-file scan)
        pyi = write("pyi.exe", make_pe(extra=b"\x00" * 300000 + b"MEI\x0c\x0b\x0a\x0b\x0e"))
        rc, data = tri(triage, pyi, "--max-read", "4096")
        check("PyInstaller cookie found past --max-read", "PyInstaller bundle (Python)" in fp_names(data), str(fp_names(data)))
        # regression: CAFEBABE disambiguation
        rc, data = tri(triage, write("Main.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\x00" * 32))
        check("Java .class (not Mach-O fat)", data.get("route_key") == "java-class", data.get("route_key"))
        fat = (b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + struct.pack(">IIIII", 0x01000007, 3, 4096, 64, 12)
               + struct.pack(">IIIII", 0x0100000c, 0, 8192, 64, 14) + b"\x00" * 32)
        rc, data = tri(triage, write("uni", fat))
        check("fat Mach-O slices", data.get("format_details", {}).get("slices") == ["x86-64", "ARM64"], str(data.get("format_details")))
        # APK + framework fingerprints
        apk = os.path.join(d, "app.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("AndroidManifest.xml", "x")
            z.writestr("classes.dex", "dex\n035\x00")
            z.writestr("lib/arm64-v8a/libflutter.so", "x")
            z.writestr("assets/index.android.bundle", b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f" + b"\x00" * 8)
        rc, data = tri(triage, apk)
        check("APK -> android", data.get("route_key") == "android", data.get("route_key"))
        check("Flutter + Hermes fingerprinted", "Flutter" in fp_names(data)
              and "React Native (Hermes bytecode)" in fp_names(data), str(fp_names(data)))
        # regression: directory mode (install dirs, macOS .app bundles)
        app = os.path.join(d, "Demo.app", "Contents")
        os.makedirs(os.path.join(app, "MacOS"))
        with open(os.path.join(app, "Info.plist"), "w") as f:
            f.write("<plist/>")
        with open(os.path.join(app, "MacOS", "Demo"), "wb") as f:
            f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)
        rc, data = tri(triage, os.path.join(d, "Demo.app"))
        markers = [m["name"] for m in data.get("directory", {}).get("app_markers", [])]
        check("directory mode works on .app bundle", rc == 0 and "Apple app bundle" in markers, str(markers))
        # malformed input must not crash
        for name, blob in (("trunc_pe", b"MZ\x00\x00"), ("trunc_elf", b"\x7fELF"), ("empty", b"")):
            rc, _ = tri(triage, write(name, blob))
            check("no crash on " + name, rc == 0)


# ---------------------------------------------------------------------------
# 3. check_tools.py runs, emits JSON, and finds Ghidra via GHIDRA_INSTALL_DIR.
# ---------------------------------------------------------------------------
def test_check_tools():
    print("\n[check_tools] runs, JSON, Ghidra env detection")
    ct = os.path.join(SCRIPTS, "check_tools.py")
    rc, out = run([ct, "--json"])
    check("check_tools rc=0", rc == 0, out[:200])
    data = json.loads(out)
    check("check_tools has by_task", "by_task" in data and "triage" in data["by_task"])
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "support"))
        env = dict(os.environ, GHIDRA_INSTALL_DIR=d)
        p = subprocess.run([PY, ct, "--json"], capture_output=True, text=True, env=env)
        check("Ghidra found via GHIDRA_INSTALL_DIR", "ghidra" in json.loads(p.stdout)["have"])


# ---------------------------------------------------------------------------
# 4. extract_endpoints.py: surface + regressions for audited flaws.
# ---------------------------------------------------------------------------
def test_extract_endpoints():
    print("\n[extract_endpoints] surface + regressions")
    ee = os.path.join(SCRIPTS, "extract_endpoints.py")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "Api.java"), "w") as f:
            f.write("package com.example.app;\nimport android.app.Activity;\nimport java.net.URL;\n")
            f.write('@GET("v2/users/{id}/profile")\n')
            f.write('String u = "https://api.example.io/v1/items/{itemId}";\n')
            f.write("OkHttpClient c; // Authorization: Bearer x\n")
            f.write('Cipher.getInstance("AES/CBC/PKCS5Padding");\n')
            f.write('String k = "AKIAABCDEFGHIJKLMNOP";\n')
        with open(os.path.join(d, "Api.smali"), "w") as f:
            f.write('    .annotation runtime Lretrofit2/http/POST;\n        value = "auth/v1/login"\n    .end annotation\n')
        with open(os.path.join(d, "bundle.min.js"), "w") as f:
            pad = "var a=function(){return 1};" * 2000
            f.write(pad + 'axios.post("/api/v3/orders",x);' + pad)
        rc, out = run([ee, d, "--json"])
        check("extract_endpoints rc=0", rc == 0, out[:200])
        f = json.loads(out)["findings"]
        check("finds url with template intact", "https://api.example.io/v1/items/{itemId}" in f["url"], str(f["url"]))
        check("finds net_lib OkHttp", "OkHttp" in f["net_lib"])
        check("finds crypto AES", "AES" in f["crypto"])
        check("Retrofit annotation endpoint", "GET v2/users/{id}/profile" in f["endpoint"], str(f["endpoint"]))
        check("smali Retrofit annotation", "POST auth/v1/login" in f["endpoint"], str(f["endpoint"]))
        check("endpoint deep in a long minified line", "POST /api/v3/orders" in f["endpoint"], str(f["endpoint"]))
        bad = [h for h in f["host"] if h in ("android.app", "java.net", "com.example.app")]
        check("package names are not reported as hosts", not bad, str(bad))
        check("secrets masked by default", bool(f["secret_ish"]) and "AKIAABCDEFGHIJKLMNOP" not in json.dumps(f["secret_ish"]))


# ---------------------------------------------------------------------------
# 5. Structure: SKILL.md frontmatter, referenced paths, manifests.
# ---------------------------------------------------------------------------
def _parse_frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return None
    fm = {}
    # tiny YAML-ish reader good enough for top-level scalar keys we need
    for line in m.group(1).splitlines():
        mm = re.match(r"^([a-zA-Z_-]+):\s*(.*)$", line)
        if mm and mm.group(2) not in (">-", "|", ">", ""):
            fm[mm.group(1)] = mm.group(2).strip()
        elif mm:
            fm.setdefault(mm.group(1), "")
    return fm


def test_structure():
    print("\n[structure] SKILL.md, references, manifests")
    skill_md = os.path.join(SKILL, "SKILL.md")
    check("SKILL.md exists", os.path.isfile(skill_md))
    text = open(skill_md, encoding="utf-8").read()
    fm = _parse_frontmatter(text)
    check("frontmatter present on line 1", fm is not None)
    check("name == reverse-engineering", fm and fm.get("name") == "reverse-engineering", fm and fm.get("name"))
    check("SKILL.md under 500 lines", text.count("\n") + 1 < 500, str(text.count("\n") + 1))

    # description length (spec cap 1024)
    dm = re.search(r"description:\s*>-\n((?:  .*\n)+)", text)
    desc_len = len(re.sub(r"\s+", " ", dm.group(1))) if dm else 0
    check("description within 1024 chars", 0 < desc_len <= 1024, str(desc_len))

    # every markdown-linked relative path resolves
    links = set(re.findall(r"\]\((references/[\w\-]+\.md|assets/[\w\-]+\.md)\)", text))
    missing = [l for l in links if not os.path.isfile(os.path.join(SKILL, l))]
    check("all SKILL.md reference links resolve", not missing, ",".join(missing))

    # every references/*.md is linked from SKILL.md
    on_disk = {"references/" + fn for fn in os.listdir(os.path.join(SKILL, "references")) if fn.endswith(".md")}
    unlinked = on_disk - links
    check("no orphan reference files", not unlinked, ",".join(sorted(unlinked)))

    # script paths named in SKILL.md exist
    spaths = set(re.findall(r"scripts/[\w./\-]+\.py", text))
    smissing = [s for s in spaths if not os.path.isfile(os.path.join(SKILL, s))]
    check("all SKILL.md script paths exist", not smissing, ",".join(smissing))

    # playbooks and scripts named inside the bundled scripts (e.g. triage routes) exist
    dangling = set()
    for dirpath, _dirs, files in os.walk(SCRIPTS):
        for fn in files:
            if fn.endswith(".py"):
                src = open(os.path.join(dirpath, fn), encoding="utf-8").read()
                for ref in re.findall(r"references/[\w\-]+\.md|scripts/[\w/\-]+\.(?:py|java)", src):
                    if not os.path.isfile(os.path.join(SKILL, ref)):
                        dangling.add(ref)
    check("no dangling references inside scripts", not dangling, ",".join(sorted(dangling)))

    # manifests are valid JSON with matching plugin names
    mp = json.load(open(os.path.join(ROOT, ".claude-plugin", "marketplace.json")))
    pj = json.load(open(os.path.join(ROOT, ".claude-plugin", "plugin.json")))
    check("marketplace.json valid + has plugins", bool(mp.get("plugins")))
    check("plugin.json name matches skill", pj.get("name") == "reverse-engineering", pj.get("name"))
    entry_names = {p["name"] for p in mp.get("plugins", [])}
    check("marketplace lists the plugin", "reverse-engineering" in entry_names, ",".join(entry_names))


def main():
    print("Testing reverse-engineering skill at:\n  " + SKILL)
    for t in (test_compile, test_triage, test_check_tools, test_extract_endpoints, test_structure):
        t()
    print("\n" + "=" * 60)
    if _failures:
        print("FAILED ({} ok, {} failed):".format(_passed, len(_failures)))
        for f in _failures:
            print("  - " + f)
        return 1
    print("ALL PASSED ({} checks)".format(_passed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
