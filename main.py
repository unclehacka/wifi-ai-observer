import json
import requests
from scapy.all import sniff, Dot11ProbeReq
from manuf import manuf  # pip install manuf

with open("config.json") as f:
    cfg = json.load(f)

API_KEY = cfg["api_key"]
INTERFACE = cfg["interface"]
DURATION = cfg["duration"]

GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={API_KEY}"

devices = {}
parser = manuf.MacParser()

def handler(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        mac = pkt.addr2
        if not mac:
            return
        try:
            ssid_raw = pkt.info
            ssid = ssid_raw.decode("utf-8", errors="ignore").strip() if isinstance(ssid_raw, bytes) else str(ssid_raw).strip()
            ssid = ''.join(c for c in ssid if 32 <= ord(c) <= 126)
        except Exception:
            ssid = ""
        if not ssid:
            return
        if mac not in devices:
            vendor = parser.get_manuf(mac) or "Unknown"
            devices[mac] = {"ssids": set(), "vendor": vendor}
        devices[mac]["ssids"].add(ssid)

print(f"[+] Sniffing {DURATION} sec on {INTERFACE}...")
sniff(iface=INTERFACE, prn=handler, store=0, timeout=DURATION)

dataset = []
for mac, info in devices.items():
    for ssid in info["ssids"]:
        dataset.append({
            "mac": mac,
            "vendor": info["vendor"],
            "ssid": ssid
        })

payload = {
    "contents": [{
        "parts": [{
            "text": (
                "Analyze the list of devices and group them by SSID. "
                "If a device searches for multiple SSIDs, include it in multiple groups. "
                "Present the result in a clear operator-friendly tree-like format:\n\n" +
                json.dumps(dataset, indent=2)
            )
        }]
    }]
}

print("[+] Sending to Gemini...")
resp = requests.post(GEMINI_URL, headers={"Content-Type": "application/json"}, json=payload)
data = resp.json()

try:
    answer = data["candidates"][0]["content"]["parts"][0]["text"]
except Exception:
    answer = str(data)

print("\n=== GROUPING RESULT ===\n")
print(answer)
