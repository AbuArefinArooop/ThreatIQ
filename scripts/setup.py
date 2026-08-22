#!/usr/bin/env python3
"""
ThreatIQ v4.0 Setup Script
Validates environment, downloads MITRE ATT&CK data, runs GAT training.
Usage: python scripts/setup.py
"""
import os, sys, json, urllib.request
from pathlib import Path

def check_python():
    if sys.version_info < (3,11):
        print("ERROR: Python 3.11+ required"); sys.exit(1)
    print(f"Python {sys.version.split()[0]} -- OK")

def check_packages():
    required = ["fastapi","uvicorn","sqlalchemy","pydantic_settings","numpy","sklearn"]
    missing = []
    for pkg in required:
        try: __import__(pkg)
        except ImportError: missing.append(pkg)
    if missing:
        print(f"Missing packages: {missing}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)
    print("All required packages installed -- OK")

def create_dirs():
    for d in ["model_artifacts","data/mitre_attack","logs"]:
        Path(d).mkdir(parents=True, exist_ok=True)
    print("Directories created -- OK")

def download_mitre():
    path = Path("data/mitre_attack/enterprise-attack.json")
    if path.exists():
        print(f"MITRE ATT&CK data already present ({path.stat().st_size//1024}KB) -- skipping")
        return
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print(f"Downloading MITRE ATT&CK data from GitHub...")
    try:
        urllib.request.urlretrieve(url, path)
        print(f"Downloaded {path.stat().st_size//1024}KB -- OK")
    except Exception as e:
        print(f"Download failed: {e}")
        print("Offline mode will be used (embedded relationships)")

def train_gat():
    print("Training GAT on MITRE ATT&CK data...")
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from app.ml.gat import GATTrainer
    trainer = GATTrainer("data/mitre_attack/enterprise-attack.json")
    metrics = trainer.train(epochs=100)
    trainer.save()
    print(f"GAT trained: Hits@5={metrics.get('hits_at_5',0):.3f}  MRR={metrics.get('mrr',0):.3f}")

def create_env():
    if Path(".env").exists():
        print(".env already exists -- skipping")
        return
    import shutil
    shutil.copy(".env.template", ".env")
    print(".env created from template -- edit to add real credentials")

if __name__ == "__main__":
    print("=" * 55)
    print("  ThreatIQ v4.0 Setup")
    print("=" * 55)
    check_python()
    check_packages()
    create_dirs()
    create_env()
    download_mitre()
    train_gat()
    print()
    print("Setup complete!")
    print("Start the server:  uvicorn app.main:app --reload")
    print("API docs:          http://localhost:8000/docs")
    print("=" * 55)
