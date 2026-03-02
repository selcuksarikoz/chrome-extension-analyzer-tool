import os
import re
import tempfile
import zipfile
import platform
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

import requests


class Downloader(ABC):
    @abstractmethod
    def download(self, url: str) -> Path:
        pass

    @abstractmethod
    def extract(self, zip_path: Path) -> Path:
        pass


class ChromeWebStoreDownloader(Downloader):
    def __init__(self, output_dir: Optional[Path] = None):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            }
        )
        self.temp_dir = Path(tempfile.mkdtemp())
        self.output_dir = output_dir or Path.cwd()
        self.version = "131.0.0.0"
        self.nacl_arch = self._get_nacl_arch()
        self.extension_name = "extension"

    def _get_nacl_arch(self) -> str:
        system = platform.system()
        machine = platform.machine()

        if system == "Darwin":
            if "arm" in machine.lower() or "aarch64" in machine.lower():
                return "arm"
            return "x86-64"
        elif system == "Windows":
            if "x64" in machine:
                return "x86-64"
            return "x86-32"
        elif system == "Linux":
            if "x86_64" in machine:
                return "x86-64"
            elif "x86" in machine:
                return "x86-32"
            elif "arm" in machine:
                return "arm"
        return "x86-64"

    def download(self, url: str) -> Path:
        extension_id = self._extract_extension_id(url)
        if not extension_id:
            raise ValueError("Invalid Chrome Extension URL")

        self.extension_id = extension_id

        page = self.session.get(url).text
        name_match = re.search(r'"name":"([^"]+)"', page)
        if name_match:
            self.extension_name = name_match.group(1).replace(" ", "_")

        download_url = self._get_download_url(extension_id)

        response = self.session.get(download_url, stream=True)

        if response.status_code == 404:
            raise ValueError(f"Extension not found or unavailable: {extension_id}")

        response.raise_for_status()

        content = response.content
        zip_data = self._convert_crx_to_zip(content)

        safe_name = re.sub(r"[^\w\-]", "_", self.extension_name)[:50]
        zip_path = self.output_dir / f"{safe_name}_{extension_id}.zip"
        zip_path.write_bytes(zip_data)

        self.downloaded_zip = zip_path

        return zip_path

    def extract(self, zip_path: Path) -> Path:
        extract_dir = self.temp_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(extract_dir)
        except zipfile.BadZipFile:
            raise ValueError("Invalid zip file - extension may not be available")

        return extract_dir

    def _convert_crx_to_zip(self, crx_data: bytes) -> bytes:
        buf = bytearray(crx_data)

        if len(buf) < 12:
            return crx_data

        magic = buf[:4]
        if magic != b"Cr24":
            return crx_data

        version = int.from_bytes(buf[4:8], "little")

        if version == 2:
            header = 16
            public_key_length = int.from_bytes(buf[8:12], "little")
            signature_length = int.from_bytes(buf[12:16], "little")
            zip_start = header + public_key_length + signature_length
        elif version == 3:
            header = 12
            public_key_length = int.from_bytes(buf[8:12], "little")
            zip_start = header + public_key_length
        else:
            return crx_data

        if zip_start >= len(buf):
            return crx_data

        return bytes(buf[zip_start:])

    def _extract_extension_id(self, url: str) -> Optional[str]:
        patterns = [
            r"chromewebstore\.google\.com/detail/[^/]+/([a-z]{32})",
            r"chrome\.google\.com/webstore/detail/[^/]+/([a-z]{32})",
            r"microsoftedge\.microsoft\.com/addons/detail/[^/]+/([a-z]{32})",
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)

        page = self.session.get(url).text
        match = re.search(r'"id":"([a-z]{32})"', page)
        if match:
            return match.group(1)

        return None

    def _get_download_url(self, extension_id: str) -> str:
        return (
            f"https://clients2.google.com/service/update2/crx?"
            f"response=redirect&prodversion={self.version}&acceptformat=crx2,crx3"
            f"&x=id%3D{extension_id}%26installsource%3Dondemand%26uc"
            f"&nacl_arch={self.nacl_arch}"
        )


class CrxExtractor:
    def extract_manifest(self, extracted_dir: Path) -> Optional[dict]:
        manifest_path = extracted_dir / "manifest.json"

        if not manifest_path.exists():
            for subdir in extracted_dir.rglob("*"):
                if subdir.is_file() and subdir.name == "manifest.json":
                    manifest_path = subdir
                    break

        if manifest_path and manifest_path.exists():
            import json

            with open(manifest_path, "r", encoding="utf-8") as f:
                return json.load(f)

        return None
