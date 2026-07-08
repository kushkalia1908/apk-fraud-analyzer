import re
import hashlib
import sys
import os
from loguru import logger
# Kill androguard's internal debug/info spam completely
logger.remove()
from androguard.core.apk import APK

# --- Get APK path: from CLI arg, or ask interactively ---
if len(sys.argv) > 1:
    APK_PATH = sys.argv[1]
else:
    APK_PATH = input("Enter APK filename (e.g. xyz.apk): ").strip()

if not os.path.isfile(APK_PATH):
    print(f"[!] File not found: {APK_PATH}")
    sys.exit(1)

# Auto-name the report based on the APK filename so multiple samples don't overwrite each other
base_name = os.path.splitext(os.path.basename(APK_PATH))[0]
OUT_FILE = f"evidence_report_{base_name}.txt"

lines = []
def out(*args):
    text = " ".join(str(a) for a in args)
    print(text)
    lines.append(text)

out("="*70)
out("FRAUD APK ANALYSIS REPORT")
out("="*70)
out("Target APK   :", APK_PATH)

# 1. HASHES
out("\n[1] FILE HASHES")
with open(APK_PATH, "rb") as f:
    data = f.read()
out("MD5   :", hashlib.md5(data).hexdigest())
out("SHA256:", hashlib.sha256(data).hexdigest())

# 2. APP IDENTITY
a = APK(APK_PATH)
out("\n[2] APP IDENTITY")
out("Package name :", a.get_package())
out("App label    :", a.get_app_name())
out("Version      :", a.get_androidversion_name())
out("Min/Target SDK:", a.get_min_sdk_version(), "/", a.get_target_sdk_version())

# 3. SIGNING CERTIFICATE
out("\n[3] SIGNING CERTIFICATE")
out("Signed v1/v2/v3:", a.is_signed_v1(), a.is_signed_v2(), a.is_signed_v3())
for cert in a.get_certificates():
    out("Subject   :", cert.subject.human_friendly)
    out("Issuer    :", cert.issuer.human_friendly)
    out("SHA256 FP :", cert.sha256_fingerprint)
    if "Android" in cert.subject.human_friendly and "Mountain View" in cert.subject.human_friendly:
        out(">>> WARNING: Signed with the PUBLIC AOSP DEBUG certificate. No legitimate app uses this.")

# 4. DANGEROUS MANIFEST FLAGS (robust raw-text approach)
out("\n[4] MANIFEST RED FLAGS")
try:
    raw_manifest = a.get_android_manifest_axml().get_xml()
except Exception:
    raw_manifest = a.get_raw()  # fallback, won't be pretty but won't crash
manifest_text = str(raw_manifest)
for flag in ["debuggable", "usesCleartextTraffic"]:
    if flag in manifest_text:
        out(f"Found manifest attribute present: {flag}")
    else:
        out(f"(not found in parsed manifest text: {flag})")

# 5. PERMISSIONS
out("\n[5] PERMISSIONS REQUESTED")
for p in a.get_permissions():
    out(" -", p)

# 6. COMPONENTS
out("\n[6] APP COMPONENTS")
out("Activities:", a.get_activities())
out("Services  :", a.get_services())
out("Receivers :", a.get_receivers())

# 7. C2 URLs + dropper/crypto evidence
out("\n[7] EMBEDDED URLS (filtered)")
ignore_domains = ["schemas.android.com", "w3.org", "jetbrains.com", "kotlinlang.org",
                   "android.com", "googleapis", "google.com", "gstatic", "material.io",
                   "github.com", "apache.org"]
evidence_keywords = [
    r"verification\.php", r"\.enc\b", r"AES/CBC", r"PackageInstaller",
    r"VpnService", r"Download URL", r"Decrypt", r"Installed Successfully",
    r"base_encrypted"
]
for dex_bytes in a.get_all_dex():
    text = dex_bytes.decode("latin-1")
    urls = set(re.findall(r'https?://[^\s"\'<>]+', text))
    real_urls = [u for u in urls if not any(d in u for d in ignore_domains)]
    for u in real_urls:
        out(" URL:", u)

out("\n[7b] DROPPER/CRYPTO BEHAVIOR EVIDENCE")
for dex_bytes in a.get_all_dex():
    text = dex_bytes.decode("latin-1")
    for kw in evidence_keywords:
        matches = set(re.findall(rf'.{{0,10}}{kw}.{{0,50}}', text, re.IGNORECASE))
        for m in matches:
            clean = m.replace("\x00", " ").strip()
            if clean:
                out(f" [{kw}] {clean}")

out("\n" + "="*70)
out("END OF REPORT")
out("="*70)

with open(OUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print(f"\n\nFull report also saved to: {OUT_FILE}")