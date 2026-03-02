from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExtensionInfo:
    url: str
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    content_scripts: list[dict] = field(default_factory=list)
    background_script: Optional[str] = None
    manifest_version: Optional[int] = None
    icons: dict = field(default_factory=dict)
    extracted_path: Optional[str] = None
    files: list[str] = field(default_factory=list)
    file_contents: dict[str, str] = field(default_factory=dict)
