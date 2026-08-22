"""
ThreatIQ v4.0 -- Synthetic data generator.
Explicitly flagged is_synthetic=True so it is NEVER silently mixed with real CTI.
Used only when real feed data is insufficient for training.
"""
import random
import numpy as np
import hashlib

SEED = 42
random.seed(SEED); np.random.seed(SEED)

IOC_CLASSES = ["Malware","Phishing","Ransomware","DDoS","APT",
               "SQL Injection","Zero-Day","Credential Stuffing","Insider Threat"]

TEMPLATES = {
    "Malware": [
        "Emotet banking trojan delivered via malspam campaign targeting financial institutions",
        "Cobalt Strike beacon communicating HTTPS to 185.220.101.x C2 infrastructure",
        "AgentTesla keylogger variant harvesting email credentials via SMTP exfiltration",
        "AsyncRAT dropped by PowerShell loader from compromised website infrastructure",
    ],
    "Phishing": [
        "Spear-phishing campaign targeting executives with fake Microsoft Teams invitations",
        "BEC attack impersonating CFO requesting urgent wire transfer to new vendor account",
        "QR code phishing bypassing email security by embedding malicious URL in image",
        "Adversary-in-the-Middle phishing using Evilginx2 to capture session tokens",
    ],
    "Ransomware": [
        "LockBit 3.0 deploying via PsExec across domain deleting VSS copies before encryption",
        "BlackCat ALPHV affiliate using Brute Ratel for lateral movement before encryption",
        "Cl0p ransomware exploiting MOVEit zero-day for data exfiltration prior to extortion",
        "Royal ransomware using partial file encryption to evade detection in healthcare",
    ],
    "DDoS": [
        "HTTP/2 Rapid Reset attack generating 398 million requests per second on gaming platform",
        "Mirai botnet variant leveraging IoT devices for 1.3 Tbps NTP amplification attack",
        "DNS water torture attack causing 89% query failure rate for target domain",
        "HTTPS flood at 46 million RPS against Cloud Armor protected infrastructure",
    ],
    "APT": [
        "APT29 conducting password spray attacks against Microsoft 365 government tenants",
        "Volt Typhoon maintaining persistent access using living-off-the-land binaries",
        "APT41 deploying KEYPLUG backdoor using Cloudflare Workers as C2 proxy",
        "Sandworm deploying AcidPour wiper against Ukrainian telecom infrastructure",
    ],
    "SQL Injection": [
        "Blind time-based SQL injection against PostgreSQL extracting credentials byte by byte",
        "Union-based SQL injection in retail application exposing 2.3M customer records",
        "SQLmap automated exploitation of login form vulnerability against MySQL database",
        "Boolean-based blind SQLi in REST API requiring 15000 requests for extraction",
    ],
    "Zero-Day": [
        "CVE-2024-3400 PAN-OS command injection exploited by UTA0218 pre-patch",
        "MOVEit Transfer CVE-2023-34362 exploited by Cl0p for mass data exfiltration",
        "Citrix Bleed CVE-2023-4966 session token hijacking against financial sector",
        "JetBrains TeamCity zero-day enabling admin account creation by SVR-linked actor",
    ],
    "Credential Stuffing": [
        "Credential stuffing using 71M leaked pairs from 2024 combo list against streaming",
        "Account takeover using residential proxy network to evade IP rate limiting",
        "Password spraying against Azure AD using common passwords across tenant accounts",
        "Automated Sentry MBA variant against gaming platform at 500k attempts per hour",
    ],
    "Insider Threat": [
        "Departing employee exfiltrating 13000 files via personal Google Drive before resignation",
        "System administrator creating covert backdoor account after receiving termination notice",
        "DLP alert bulk download of source code by developer during after-hours access",
        "Former employee retaining VPN access post-termination accessing HR from foreign IP",
    ],
}

SEVERITIES = {1:"Informational",2:"Low",3:"Medium",4:"High",5:"Critical"}
SEV_WEIGHTS = {
    "Malware":[2,8,25,40,25],"Phishing":[2,10,30,38,20],"Ransomware":[1,4,15,35,45],
    "DDoS":[3,10,28,38,21],"APT":[1,3,12,33,51],"SQL Injection":[2,8,28,40,22],
    "Zero-Day":[1,3,10,28,58],"Credential Stuffing":[2,8,28,40,22],"Insider Threat":[2,10,25,38,25],
}

def _gen_ioc(cls, rng):
    if cls in ["Malware","Ransomware","Zero-Day"]:
        return hashlib.sha256(f"{rng.randint(0,999999)}".encode()).hexdigest()
    if cls in ["Phishing","APT"]:
        suf=["com","net","org","io","xyz"]
        return f"{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz',k=8))}.{rng.choice(suf)}"
    if cls in ["DDoS","Credential Stuffing"]:
        return f"{rng.choice(['185.220','198.51','91.108'])}.{rng.randint(0,255)}.{rng.randint(1,254)}"
    if cls=="SQL Injection":
        return f"hxxps://target[.]com/q=1+OR+{rng.randint(1,9)}=1--"
    if cls=="Insider Threat":
        return f"{rng.choice(['jsmith','a.doe','m.lee'])}@corp.com"
    return hashlib.md5(str(rng.random()).encode()).hexdigest()[:16]

def _ioc_type(cls):
    m={"Malware":"File Hash (SHA256)","Ransomware":"File Hash (SHA256)",
       "Zero-Day":"CVE Identifier","Phishing":"Domain Name","APT":"Domain Name",
       "DDoS":"IPv4 Address","Credential Stuffing":"IPv4 Address",
       "SQL Injection":"URL Pattern","Insider Threat":"User Account"}
    return m.get(cls,"Indicator")

CLASS_WEIGHTS = [0.18,0.17,0.14,0.12,0.10,0.11,0.08,0.07,0.03]
SOURCES = ["MISP","CIRCL","FS-ISAC","Internal SIEM","VirusTotal",
           "Shodan","OTX AlienVault","IBM X-Force","Recorded Future","STIX/TAXII"]
SOURCE_TRUST = {"MISP":0.90,"CIRCL":0.92,"FS-ISAC":0.88,"Internal SIEM":0.85,
                "VirusTotal":0.82,"Shodan":0.75,"OTX AlienVault":0.78,
                "IBM X-Force":0.84,"Recorded Future":0.86,"STIX/TAXII":0.90}


def generate_synthetic_iocs(n: int = 2000, seed: int = SEED) -> list[dict]:
    """
    Generate synthetic IoCs EXPLICITLY marked is_synthetic=True.
    Used for training when real data is insufficient.
    NEVER mix with real data without explicit is_synthetic filtering.
    """
    rng = random.Random(seed)
    np.random.seed(seed)
    classes = rng.choices(IOC_CLASSES, weights=CLASS_WEIGHTS, k=n)
    iocs = []
    for i, cls in enumerate(classes):
        tmpl = TEMPLATES[cls]
        text = tmpl[i % len(tmpl)]
        # add noise
        if rng.random() < 0.08:
            noise_cls = rng.choice([c for c in IOC_CLASSES if c != cls])
            text = TEMPLATES[noise_cls][0] + " " + text.split()[0]
        sev = rng.choices([1,2,3,4,5], weights=SEV_WEIGHTS[cls])[0]
        src = rng.choice(SOURCES)
        conf = round(float(np.random.beta(8,2)),2)
        comp = float(np.clip(0.4*(sev-1)/4 + 0.3*(1-SOURCE_TRUST[src]) + 0.3*np.random.normal(0.05,0.25),-0.4,1.0))
        iocs.append({
            "text": text, "label": cls, "severity": sev,
            "severity_label": SEVERITIES[sev], "confidence": conf,
            "source": src, "source_trust": SOURCE_TRUST[src],
            "composite_score": round(comp,4),
            "anomaly_score": round(comp + float(np.random.normal(0,0.04)),4),
            "ioc_value": _gen_ioc(cls, rng), "ioc_type": _ioc_type(cls),
            "tlp": rng.choice(["TLP:WHITE","TLP:GREEN","TLP:AMBER","TLP:RED"]),
            "is_synthetic": True,   # EXPLICIT FLAG -- never hide this
            "external_id": f"SYN-{seed}-{i:06d}",
        })
    return iocs
