from .extension import ExtensionInfo
from typing import Optional


class ManifestAnalyzer:
    def __init__(self):
        self.dangerous_permissions = {
            "tabs",
            "activeTab",
            "cookies",
            "storage",
            "webRequest",
            "webRequestBlocking",
            "history",
            "bookmarks",
            "debugger",
            "pageCapture",
            "proxy",
            "management",
            "clipboardRead",
            "clipboardWrite",
            "downloads",
            "geolocation",
            "nativeMessaging",
        }

    def analyze(self, manifest: dict, extension_info: ExtensionInfo) -> ExtensionInfo:
        extension_info.manifest_version = manifest.get("manifest_version")
        extension_info.name = manifest.get("name", "Unknown")
        extension_info.version = manifest.get("version")
        extension_info.description = manifest.get("description")

        perms = manifest.get("permissions", [])
        host_perms = manifest.get("host_permissions", [])

        if isinstance(perms, list):
            extension_info.permissions = perms
        if isinstance(host_perms, list):
            extension_info.host_permissions = host_perms

        extension_info.background_script = self._extract_background(manifest)
        extension_info.content_scripts = self._extract_content_scripts(manifest)
        extension_info.icons = manifest.get("icons", {})

        return extension_info

    def _extract_background(self, manifest: dict) -> Optional[str]:
        if "background" in manifest:
            bg = manifest["background"]
            if "service_worker" in bg:
                return bg["service_worker"]
            if "scripts" in bg and bg["scripts"]:
                return bg["scripts"][0]
        return None

    def _extract_content_scripts(self, manifest: dict) -> list[dict]:
        return manifest.get("content_scripts", [])

    def get_risk_level(self, extension_info: ExtensionInfo) -> str:
        high_risk = [
            p for p in extension_info.permissions if p in self.dangerous_permissions
        ]

        if any(
            "all_urls" in p or "<all_urls>" in p
            for p in extension_info.host_permissions
        ):
            return "VERY HIGH"

        if high_risk:
            return "HIGH"
        return "LOW"
