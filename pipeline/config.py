"""Central configuration for the pinning-measurement pipeline.

Everything machine-specific (device ids, IPs, credentials, tool paths) comes from
environment variables or an optional .env file, never hardcoded. A lesson from
paper 1: hardcoded device UUIDs, API keys, and per-user home paths scattered
across scripts made it unrunnable on a second machine. Here there is one config.

Load order: real environment variables override values in a `.env` file at the
project root, which overrides the defaults below.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no dependency). KEY=VALUE lines, # comments."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(PROJECT_ROOT / ".env")


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_path(key: str, default: Path) -> Path:
    val = os.environ.get(key)
    return Path(val).expanduser() if val else default


def _env_list(key: str, default: list[str]) -> list[str]:
    val = os.environ.get(key)
    if not val:
        return default
    return [x.strip() for x in val.split(",") if x.strip()]


# Storefronts to crawl (ISO country codes). Same set as paper 1 by default.
STOREFRONTS: list[str] = _env_list("STOREFRONTS", ["us", "gb", "ca", "cn", "jp"])

# Pinning-heavy categories to stratify on, by iTunes genre id.
# 6015 Finance, 6023 Business, 6013 Health & Fitness, 6012 Lifestyle (dating),
# 6005 Social Networking, 6000 Business... (ids validated at crawl time).
STRATA_GENRES: dict[str, str] = {
    "6015": "Finance",
    "6023": "Business",
    "6013": "Health & Fitness",
    "6005": "Social Networking",
    "6012": "Lifestyle",
    "6018": "Books",
    "6002": "Utilities",
    "6008": "Photo & Video",
}

# Per-category rank depth to scrape.
CRAWL_COUNT_PER_CATEGORY: int = int(_env("CRAWL_COUNT_PER_CATEGORY", "500"))


@dataclass(frozen=True)
class Paths:
    root: Path = PROJECT_ROOT
    db: Path = field(default_factory=lambda: _env_path("PIPELINE_DB", PROJECT_ROOT / "pinning.db"))
    # IPAs are large; default to an external drive if provided via env.
    ipa_dir: Path = field(default_factory=lambda: _env_path("IPA_DIR", PROJECT_ROOT / "ipas"))
    work_dir: Path = field(default_factory=lambda: _env_path("WORK_DIR", PROJECT_ROOT / "work"))
    results_dir: Path = field(default_factory=lambda: _env_path("RESULTS_DIR", PROJECT_ROOT / "results"))
    log_dir: Path = field(default_factory=lambda: _env_path("LOG_DIR", PROJECT_ROOT / "logs"))
    dylib_dir: Path = field(default_factory=lambda: _env_path("DYLIB_DIR", PROJECT_ROOT))

    def ensure(self) -> None:
        for p in (self.ipa_dir, self.work_dir, self.results_dir, self.log_dir):
            p.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class DecryptDevice:
    """Jailbroken iPhone 8 used only for FairPlay decryption via ipadecrypt."""
    ssh_host: str = field(default_factory=lambda: _env("DECRYPT_SSH_HOST", ""))
    ssh_user: str = field(default_factory=lambda: _env("DECRYPT_SSH_USER", "root"))
    ssh_port: int = field(default_factory=lambda: int(_env("DECRYPT_SSH_PORT", "22")))
    # Path to the ipadecrypt helper/CLI as invoked from the Mac host.
    ipadecrypt_cmd: str = field(default_factory=lambda: _env("IPADECRYPT_CMD", "ipadecrypt"))

    @property
    def bootstrap_config(self) -> Path:
        """ipadecrypt stores device/App-Store setup here after `bootstrap`."""
        return Path.home() / ".ipadecrypt" / "config.json"

    @property
    def is_bootstrapped(self) -> bool:
        return self.bootstrap_config.exists()


@dataclass(frozen=True)
class IpaTool:
    """Optional downloader: ipatool fetches the still-encrypted IPA, then
    ipadecrypt decrypts the local file. Alternative to letting ipadecrypt do the
    download itself. ipatool downloads from the logged-in account's storefront."""
    cmd: str = field(default_factory=lambda: _env("IPATOOL_CMD", "ipatool"))
    email: str = field(default_factory=lambda: _env("IPATOOL_EMAIL", ""))
    password: str = field(default_factory=lambda: _env("IPATOOL_PASSWORD", ""))


@dataclass(frozen=True)
class AppStore:
    """Alternative downloader (ACQUIRE_MODE=appstore): speaks the MZStore
    protocol directly, taking auth material (guid/kbsync/headers) from a real
    iTunes running on a Windows VM (the "iTunes server"). Not throttled like
    headless ipatool. Downloads the encrypted IPA; the iPhone 8 then decrypts."""
    itunes_server: str = field(default_factory=lambda: _env("ITUNES_SERVER", "http://10.211.55.10:9000"))


@dataclass(frozen=True)
class TestDevice:
    """Non-jailbroken iPhone XR used for all bypass testing."""
    udid: str = field(default_factory=lambda: _env("TEST_DEVICE_UDID", ""))
    client_ip: str = field(default_factory=lambda: _env("TEST_DEVICE_IP", ""))


@dataclass(frozen=True)
class Appium:
    """UI automation server + WebDriverAgent signing for the non-JB device.

    WDA must be code-signed for a real device. Provide the Apple Developer Team
    ID (org id) and a signing identity so Appium builds and signs WDA itself.
    """
    server_url: str = field(default_factory=lambda: _env("APPIUM_URL", "http://127.0.0.1:4723"))
    xcode_org_id: str = field(default_factory=lambda: _env("APPIUM_TEAM_ID", ""))       # e.g. 8CG9QYMSR5
    xcode_signing_id: str = field(default_factory=lambda: _env("APPIUM_SIGNING_ID", "Apple Development"))
    wda_bundle_id: str = field(default_factory=lambda: _env("APPIUM_WDA_BUNDLE", ""))   # e.g. com.you.WebDriverAgentRunner

    @property
    def configured(self) -> bool:
        return bool(self.xcode_org_id)


@dataclass(frozen=True)
class Proxyman:
    cli: str = field(default_factory=lambda: _env(
        "PROXYMAN_CLI", "/Applications/Proxyman.app/Contents/MacOS/proxyman-cli"))
    port: int = field(default_factory=lambda: int(_env("PROXYMAN_PORT", "9090")))


@dataclass(frozen=True)
class Signing:
    """Re-signing assets. zsign wants a PEM + mobileprovision; if only a .p12 is
    present, instrument.py exports the PEM from it using the password below."""
    zsign: Path = field(default_factory=lambda: _env_path("ZSIGN", PROJECT_ROOT.parent / "zsign"))
    p12: Path = field(default_factory=lambda: _env_path("SIGN_P12", PROJECT_ROOT.parent / "Certs" / "Certificates.p12"))
    pem: Path = field(default_factory=lambda: _env_path("SIGN_PEM", PROJECT_ROOT.parent / "Certs" / "dis.pem"))
    mobileprovision: Path = field(default_factory=lambda: _env_path(
        "SIGN_PROFILE", PROJECT_ROOT.parent / "Certs" / "amir.mobileprovision"))
    p12_password: str = field(default_factory=lambda: _env("SIGN_P12_PASSWORD", ""))


@dataclass(frozen=True)
class Dylibs:
    """Prebuilt bypass dylibs living in the project root."""
    ssks: str = field(default_factory=lambda: _env("DYLIB_SSKS", "SSLKillSwitch2.dylib"))
    sideloadfix: str = field(default_factory=lambda: _env("DYLIB_SIDELOADFIX", "sideloadFixerLol.dylib"))
    frida_gadget: str = field(default_factory=lambda: _env("DYLIB_FRIDA", "FridaGadget.dylib"))
    # Name to which the Frida gadget / SSKS is renamed to dodge anti-Frida name scans.
    frida_alias: str = field(default_factory=lambda: _env("DYLIB_FRIDA_ALIAS", "ChromaBridge.dylib"))
    ssks_alias: str = field(default_factory=lambda: _env("DYLIB_SSKS_ALIAS", "libAudioBridge.dylib"))


@dataclass(frozen=True)
class Runtime:
    # Seconds to exercise the app while capturing (paper 1 used a flat 15s cold
    # launch; we drive the UI, so this is a ceiling per interaction pass).
    monitor_seconds: int = field(default_factory=lambda: int(_env("MONITOR_SECONDS", "45")))
    # Hosts never intercepted (Apple infra), extended at runtime.
    excluded_hosts: list[str] = field(default_factory=lambda: _env_list(
        "EXCLUDED_HOSTS", ["apple.com", "icloud.com", "itunes.apple.com", "mzstatic.com"]))


# Acquisition mode: "ipadecrypt" (ipadecrypt downloads + decrypts, supports
# --storefront for multi-country) or "ipatool" (ipatool downloads encrypted,
# ipadecrypt decrypts the local file; downloads from the account storefront).
ACQUIRE_MODE: str = _env("ACQUIRE_MODE", "ipadecrypt")


@dataclass(frozen=True)
class Config:
    paths: Paths = field(default_factory=Paths)
    decrypt_device: DecryptDevice = field(default_factory=DecryptDevice)
    ipatool: IpaTool = field(default_factory=IpaTool)
    appstore: AppStore = field(default_factory=AppStore)
    test_device: TestDevice = field(default_factory=TestDevice)
    appium: Appium = field(default_factory=Appium)
    proxyman: Proxyman = field(default_factory=Proxyman)
    signing: Signing = field(default_factory=Signing)
    dylibs: Dylibs = field(default_factory=Dylibs)
    runtime: Runtime = field(default_factory=Runtime)
    acquire_mode: str = ACQUIRE_MODE

    def missing_for_dynamic(self) -> list[str]:
        """Return human-readable list of config needed before on-device stages."""
        missing = []
        if not self.test_device.udid:
            missing.append("TEST_DEVICE_UDID (iPhone XR udid from `idevice_id -l`)")
        if not self.test_device.client_ip:
            missing.append("TEST_DEVICE_IP (XR IP on the test network)")
        if not self.decrypt_device.is_bootstrapped:
            missing.append("ipadecrypt not bootstrapped (run `ipadecrypt bootstrap` once; "
                           "creates ~/.ipadecrypt/config.json)")
        if not (self.signing.pem.exists() or self.signing.p12.exists()):
            missing.append("signing cert (SIGN_PEM or SIGN_P12)")
        if not self.signing.mobileprovision.exists():
            missing.append("SIGN_PROFILE (wildcard .mobileprovision with XR udid)")
        return missing


CONFIG = Config()
