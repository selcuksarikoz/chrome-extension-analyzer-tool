from .extension import ExtensionInfo
from dataclasses import dataclass


@dataclass
class ManifestData:
    name: str
    version: str
    manifest_version: int
    permissions: list[str]
    host_permissions: list[str]
    content_scripts: list[dict]
    background: dict
    icons: dict
    description: str
