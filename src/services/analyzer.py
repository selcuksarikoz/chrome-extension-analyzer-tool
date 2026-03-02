from pathlib import Path
import re
import shutil
from typing import Optional

from src.models.extension import ExtensionInfo
from src.models.manifest import ManifestAnalyzer
from src.services.downloader import ChromeWebStoreDownloader, CrxExtractor


class ExtensionAnalyzer:
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = output_dir or Path.cwd()
        self.downloader = ChromeWebStoreDownloader(output_dir=self.output_dir)
        self.extractor = CrxExtractor()
        self.manifest_analyzer = ManifestAnalyzer()

    def analyze(self, url: str) -> tuple[ExtensionInfo, Path]:
        extension_info = ExtensionInfo(url=url, name="Analyzing...")

        zip_path = self.downloader.download(url)
        extracted_dir = self.downloader.extract(zip_path)

        manifest = self.extractor.extract_manifest(extracted_dir)
        if not manifest:
            raise ValueError("manifest.json not found!")

        extension_info = self.manifest_analyzer.analyze(manifest, extension_info)

        extension_folder = self._move_to_extension_folder(
            zip_path, extracted_dir, extension_info.name
        )

        extension_info.extracted_path = str(extension_folder)

        self._scan_files(extension_info, extension_folder)

        return extension_info, extension_folder

    def _move_to_extension_folder(
        self, zip_path: Path, extracted_dir: Path, extension_name: str
    ) -> Path:
        safe_name = re.sub(r"[^\w\-_]", "_", extension_name)[:50]
        extension_folder = self.output_dir / safe_name

        if extension_folder.exists():
            shutil.rmtree(extension_folder)

        extension_folder.mkdir(exist_ok=True)

        new_zip_path = extension_folder / "extension.zip"
        zip_path.rename(new_zip_path)
        self.downloader.downloaded_zip = new_zip_path

        for item in extracted_dir.iterdir():
            dest = extension_folder / item.name
            if item.is_dir():
                shutil.move(str(item), str(dest))
            else:
                item.rename(dest)

        self.downloader.temp_dir = extension_folder

        return extension_folder

    def _scan_files(self, info: ExtensionInfo, extracted_dir: Path):
        for file_path in extracted_dir.rglob("*"):
            if file_path.is_file():
                rel_path = str(file_path.relative_to(extracted_dir))
                info.files.append(rel_path)

                if file_path.suffix in [".js", ".json", ".html", ".css", ".txt"]:
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        if len(content) < 50000:
                            info.file_contents[rel_path] = content
                    except Exception:
                        pass

    def analyze_and_report(self, url: str) -> str:
        info, extension_folder = self.analyze(url)
        report = self._generate_markdown_report(info)

        report_path = extension_folder / "report.md"
        report_path.write_text(report)

        print(f"\n📁 Saved to: {extension_folder}")
        return report

    def _generate_markdown_report(self, info: ExtensionInfo) -> str:
        risk = self.manifest_analyzer.get_risk_level(info)
        zip_path = self.downloader.downloaded_zip

        md = f"""# Extension Analysis Report

## Info
- **Name:** {info.name}
- **Version:** {info.version or "Unknown"}
- **Manifest:** v{info.manifest_version or "?"}
- **Risk:** {risk}
- **Downloaded:** `{zip_path.name}`

## Permissions
"""

        if info.permissions:
            for perm in info.permissions:
                mark = (
                    "⚠️"
                    if perm in self.manifest_analyzer.dangerous_permissions
                    else "✅"
                )
                md += f"- {mark} `{perm}`\n"
        else:
            md += "_None_\n"

        if info.host_permissions:
            md += f"\n### Host Permissions\n"
            for host in info.host_permissions:
                mark = "⚠️" if "*" in host else "✅"
                md += f"- {mark} `{host}`\n"

        if info.content_scripts:
            md += f"\n## Content Scripts\n"
            for cs in info.content_scripts:
                matches = cs.get("matches", [])
                js_files = cs.get("js", [])
                css_files = cs.get("css", [])
                md += f"\n**Matches:** `{', '.join(matches)}`\n"
                if js_files:
                    md += f"  - JS: `{', '.join(js_files)}`\n"
                if css_files:
                    md += f"  - CSS: `{', '.join(css_files)}`\n"

        if info.background_script:
            md += f"\n## Background\n`{info.background_script}`\n"

        md += f"\n## Files ({len(info.files)})\n"
        for f in sorted(info.files):
            md += f"- `{f}`\n"

        patterns = self._find_interesting_patterns(info)
        if patterns:
            md += f"\n## Findings\n"
            for pattern in patterns:
                md += f"- {pattern}\n"

        return md

    def _find_interesting_patterns(self, info: ExtensionInfo) -> list[str]:
        findings = []

        for path, content in info.file_contents.items():
            if "apiKey" in content or "api_key" in content:
                findings.append(f"🔑 API key in `{path}`")
            if "eval(" in content:
                findings.append(f"⚠️ eval() in `{path}`")
            if "innerHTML" in content:
                findings.append(f"🔓 innerHTML in `{path}`")
            if "fetch(" in content or "XMLHttpRequest" in content:
                findings.append(f"🌐 Network in `{path}`")
            if "localStorage" in content or "sessionStorage" in content:
                findings.append(f"💾 Storage in `{path}`")
            if "chrome.cookies" in content:
                findings.append(f"🍪 Cookies in `{path}`")
            if "chrome.webRequest" in content:
                findings.append(f"🌐 WebRequest in `{path}`")

        return findings[:10]
