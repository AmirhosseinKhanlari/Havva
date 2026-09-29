"""App Store IPA downloader (alternative to ipatool).

Speaks the StoreKit / MZStore protocol directly, but takes its auth material
(guid, kbsync, X-Apple headers) from a real iTunes running on a Windows VM
(the "iTunes server"), instead of a headless Apple-ID login. That auth path is
not rate-limited/flagged the way `ipatool`'s datacenter logins are, so it is the
scalable acquisition backend.

It downloads the still-ENCRYPTED IPA (with the account's FairPlay .sinf embedded),
exactly like ipatool does; the iPhone 8 then decrypts it with ipadecrypt. So the
only thing that changes vs the ipatool path is how the encrypted IPA is fetched.

Vendored protocol lives in pipeline/appstore/ (from ipatool-py). This module is a
thin, resumable wrapper over it.
"""
from __future__ import annotations

import logging
import os
import plistlib
import time
import zipfile

import requests

from .appstore.store import StoreClient, StoreException, CONFIGURATOR_UA
from .appstore.itunes import iTunesClient

log = logging.getLogger("appstore")

_download_sess = requests.Session()
_download_sess.headers = {"User-Agent": CONFIGURATOR_UA}


def _download_file(url: str, outfile: str, retries: int = 6) -> None:
    """Stream a URL to disk, verifying the full Content-Length."""
    last = None
    for attempt in range(retries):
        try:
            with _download_sess.get(url, stream=True, timeout=30.0) as r:
                r.raise_for_status()
                total = int(r.headers.get("Content-Length", "0"))
                if not total:
                    raise RuntimeError("server returned no Content-Length")
                got = 0
                with open(outfile, "wb") as f:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            f.write(chunk)
                            got += len(chunk)
                if got != total:
                    raise RuntimeError(f"incomplete download {got}/{total}")
            return
        except Exception as e:  # noqa: BLE001 - retry any transport error
            last = e
            log.warning("  download retry %d/%d: %s", attempt + 1, retries, e)
            if os.path.exists(outfile):
                try:
                    os.remove(outfile)
                except OSError:
                    pass
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"failed to download after {retries} retries: {last}")


def _make_itunes_provider(server_url: str):
    """Return a provider that fetches per-request auth material from the Windows
    iTunes server. The server takes the target Apple URL and returns guid /
    kbsync / headers (+ optional sbsync / afds) captured from real iTunes."""
    def provider(url: str) -> dict:
        r = requests.get(server_url, params={"url": url}, timeout=30.0)
        r.raise_for_status()
        ret = r.json()
        handled = {
            "headers": ret.pop("headers"),
            "kbsync": bytes.fromhex(ret.pop("kbsync")),
            "guid": ret.pop("guid"),
        }
        if "sbsync" in ret:
            handled["sbsync"] = bytes.fromhex(ret.pop("sbsync"))
        if "afds" in ret:
            handled["afds"] = ret.pop("afds")
        return handled
    return provider


def _store_client(server_url: str) -> StoreClient:
    store = StoreClient(requests.Session())
    store.iTunes_provider = _make_itunes_provider(server_url)
    return store


def _embed_sinf_and_metadata(filepath: str, down_info) -> None:
    """Write the FairPlay .sinf(s) and iTunesMetadata.plist into the IPA, so the
    file carries the account's license (required for on-device decryption)."""
    metadata = down_info.metadata.as_dict()
    if not zipfile.is_zipfile(filepath):
        raise RuntimeError("downloaded file is not a valid IPA/zip")
    with zipfile.ZipFile(filepath, "a") as ipa:
        ipa.writestr(
            zipfile.ZipInfo("iTunesMetadata.plist", time.gmtime()[:6]),
            plistlib.dumps(metadata),
        )
        app_dirs = [
            c.rstrip("/") for c in ipa.namelist()
            if c.startswith("Payload/") and c.strip("/").count("/") == 1
            and c.rstrip("/").endswith(".app")
        ]
        if len(app_dirs) != 1:
            raise RuntimeError(f"cannot locate .app dir, choices={app_dirs}")
        app_dir = app_dirs[0]

        manifest_path = app_dir + "/SC_Info/Manifest.plist"
        sinfs = {c.id: c.sinf for c in down_info.sinfs}
        if manifest_path in ipa.namelist():
            manifest = plistlib.loads(ipa.read(manifest_path))
            for i, sinf_path in enumerate(manifest.get("SinfPaths", [])):
                ipa.writestr(app_dir + "/" + sinf_path, sinfs[i])
        else:
            info = plistlib.loads(ipa.read(app_dir + "/Info.plist"))
            sinf_path = app_dir + "/SC_Info/" + info["CFBundleExecutable"] + ".sinf"
            ipa.writestr(sinf_path, down_info.sinfs[0].sinf)


def lookup_app_id(bundle_id: str, country: str = "US") -> str | None:
    """Resolve a bundle id to its numeric App Store id."""
    it = iTunesClient(requests.Session())
    infos = it.lookup(bundleId=bundle_id, country=country)
    if infos.resultCount != 1:
        return None
    return str(infos.results[0].trackId)


def list_versions(app_id: str, server_url: str, limit: int | None = None
                  ) -> list[dict]:
    """Return the app's historical versions, newest first, as
    [{verId, shortVersion}]. Each entry costs one MZStore request (the store
    only reveals the short version per external version id), so pass `limit` to
    cap how many of the newest builds to resolve."""
    store = _store_client(server_url)
    resp = store.download(app_id, "", isRedownload=True)
    if not resp.songList:
        return []
    ver_ids = list(resp.songList[0].metadata.softwareVersionExternalIdentifiers)
    ver_ids.reverse()  # newest first
    if limit:
        ver_ids = ver_ids[:limit]
    out = []
    for vid in ver_ids:
        try:
            r = store.download(app_id, str(vid), isRedownload=True)
            if r.songList:
                out.append({"verId": str(vid),
                            "shortVersion": r.songList[0].metadata.bundleShortVersionString})
        except StoreException as e:
            log.warning("  version %s not retrievable: %s", vid, e.errMsg)
    return out


def resolve_version(app_id: str, short_or_verid: str, server_url: str) -> str | None:
    """Map a user-supplied version to a numeric externalVersionId. A bare number
    is treated as a verId already; a dotted string (e.g. '1.0.5') is looked up in
    the version history."""
    if short_or_verid and "." not in short_or_verid:
        return short_or_verid  # already a verId
    for v in list_versions(app_id, server_url):
        if v["shortVersion"] == short_or_verid:
            return v["verId"]
    return None


def download_encrypted(app_id: str, out_dir: str, server_url: str,
                       country: str = "US", app_ver_id: str | None = None
                       ) -> tuple[bool, str, str]:
    """Download the still-encrypted IPA for a numeric app id via the iTunes
    server. Returns (ok, path, error). The .sinf license is embedded so the
    iPhone 8 can decrypt it afterwards.

    Tries STDQ (acquire the license, needed for not-yet-owned apps) first, then
    falls back to STDRDL (redownload an already-owned app)."""
    os.makedirs(out_dir, exist_ok=True)
    store = _store_client(server_url)

    last_err = ""
    for is_redownload in (False, True):  # STDQ (acquire) first, then STDRDL
        try:
            resp = store.download(app_id, app_ver_id or "", isRedownload=is_redownload)
            if not resp.songList:
                last_err = "no songList in download response"
                continue
            info = resp.songList[0]
            bundle = info.metadata.softwareVersionBundleId
            ver = info.metadata.bundleShortVersionString
            filename = f"{bundle}-v{ver}-{info.songId}.ipa"
            path = os.path.join(out_dir, filename)
            log.info("  appstore: downloading %s (%s) via iTunes server ...", bundle, ver)
            _download_file(info.URL, path)
            _embed_sinf_and_metadata(path, info)
            log.info("  appstore: got %.1f MB -> %s",
                     os.path.getsize(path) / (1024 * 1024), filename)
            return True, path, ""
        except StoreException as e:
            last_err = str(e.errMsg or e)
            # Already owned -> retry as redownload; otherwise surface the error.
            if "purchased" in last_err.lower() or "license" in last_err.lower():
                continue
            return False, "", last_err
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            return False, "", last_err
    return False, "", last_err or "appstore download failed"
