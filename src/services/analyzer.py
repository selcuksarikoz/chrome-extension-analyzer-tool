from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import re
import shutil
from typing import Optional

from src.models.extension import ExtensionInfo
from src.models.manifest import ManifestAnalyzer
from src.services.downloader import ChromeWebStoreDownloader, CrxExtractor
from src.services.ai_analyzer import OpenRouterAnalyzer


class ExtensionAnalyzer:
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = (output_dir or Path.cwd()) / "extensions"
        self.output_dir.mkdir(exist_ok=True)
        self.downloader = ChromeWebStoreDownloader(output_dir=self.output_dir)
        self.extractor = CrxExtractor()
        self.manifest_analyzer = ManifestAnalyzer()
        self.ai_analyzer = OpenRouterAnalyzer()

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
        # 1. Download
        print("\n📥 Downloading extension...")
        info, extension_folder = self.analyze(url)
        print(f"✅ Download complete! ({len(info.files)} files)")

        # 2. Show our static analysis
        self._print_static_analysis(info)

        # 3. AI Analysis
        print("\n" + "=" * 60)
        print("🤖 AI ANALYSIS STARTED")
        print("=" * 60)
        ai_result = self._run_ai_analysis_with_spinner(info)

        # 4. Save and show final report
        report = self._generate_markdown_report(info, ai_result)
        report_path = extension_folder / "report.md"
        report_path.write_text(report)

        self._print_final_report(info, ai_result, extension_folder)

        return report

    def _print_static_analysis(self, info: ExtensionInfo):
        risk = self.manifest_analyzer.get_risk_level(info)
        risk_color = {"VERY HIGH": "🔴", "HIGH": "🟠", "LOW": "🟢"}.get(risk, "⚪")

        print("\n" + "=" * 60)
        print("🔍 STATIC ANALYSIS (Our Analysis)")
        print("=" * 60)

        print(f"\n📌 INFO")
        print(f"   Name:     {info.name}")
        print(f"   Version:  {info.version or 'Unknown'}")
        print(f"   Manifest: v{info.manifest_version or '?'}")
        print(f"   Risk:     {risk_color} {risk}")

        print(f"\n🔐 PERMISSIONS ({len(info.permissions)})")
        if info.permissions:
            for perm in info.permissions[:15]:
                mark = (
                    "⚠️ "
                    if perm in self.manifest_analyzer.dangerous_permissions
                    else "  "
                )
                print(f"   {mark}{perm}")
            if len(info.permissions) > 15:
                print(f"   ... and {len(info.permissions) - 15} more")
        else:
            print("   None")

        if info.host_permissions:
            print(f"\n🌐 HOST PERMISSIONS ({len(info.host_permissions)})")
            for host in info.host_permissions[:10]:
                mark = "⚠️ " if "*" in host else "  "
                print(f"   {mark}{host}")
            if len(info.host_permissions) > 10:
                print(f"   ... and {len(info.host_permissions) - 10} more")

        if info.content_scripts:
            print(f"\n📝 CONTENT SCRIPTS ({len(info.content_scripts)})")
            for cs in info.content_scripts[:5]:
                matches = cs.get("matches", [])
                print(f"   Matches: {', '.join(matches)[:50]}")

        if info.background_script:
            print(f"\n⚙️  BACKGROUND: {info.background_script}")

        patterns = self._find_interesting_patterns(info)
        if patterns:
            print(f"\n🚨 SECURITY FINDINGS ({len(patterns)})")
            for pattern in patterns[:10]:
                print(f"   {pattern}")

    def _run_ai_analysis_with_spinner(self, info: ExtensionInfo) -> Optional[str]:
        from threading import Thread
        import time
        from typing import List

        ai_result: List[Optional[str]] = [None]  # type: ignore
        ai_done: List[bool] = [False]

        def ai_worker():
            ai_result[0] = self.ai_analyzer.analyze_extension(info)
            ai_done[0] = True

        thread = Thread(target=ai_worker)
        thread.start()

        spinner = ["⏳", "⌛"]
        idx = 0
        while not ai_done[0]:
            print(f"\r{spinner[idx % 2]} AI analyzing code...", end="", flush=True)
            idx += 1
            time.sleep(0.5)

        thread.join()
        print("\r✅ AI analysis completed!               ")

        if ai_result[0] is None:
            print("ℹ️  AI analysis skipped (add OPENROUTER_API_KEY to .env)")

        return ai_result[0]

    def _print_final_report(
        self, info: ExtensionInfo, ai_analysis: Optional[str], folder: Path
    ):
        risk = self.manifest_analyzer.get_risk_level(info)
        risk_color = {"VERY HIGH": "🔴", "HIGH": "🟠", "LOW": "🟢"}.get(risk, "⚪")

        print("\n" + "=" * 60)
        print("📊 FINAL ANALYSIS REPORT")
        print("=" * 60)

        print(f"\n📌 INFO")
        print(f"   Name:     {info.name}")
        print(f"   Version:  {info.version or 'Unknown'}")
        print(f"   Manifest: v{info.manifest_version or '?'}")
        print(f"   Risk:     {risk_color} {risk}")

        if ai_analysis:
            print(f"\n🤖 AI SECURITY ANALYSIS")
            print("-" * 60)
            for line in ai_analysis.split("\n")[:20]:
                if line.strip():
                    print(f"   {line}")
            if len(ai_analysis.split("\n")) > 20:
                print(f"   ... (see full report in {folder}/report.md)")

        print(f"\n🔐 PERMISSIONS ({len(info.permissions)})")
        if info.permissions:
            for perm in info.permissions[:15]:
                mark = (
                    "⚠️ "
                    if perm in self.manifest_analyzer.dangerous_permissions
                    else "  "
                )
                print(f"   {mark}{perm}")
            if len(info.permissions) > 15:
                print(f"   ... and {len(info.permissions) - 15} more")
        else:
            print("   None")

        if info.host_permissions:
            print(f"\n🌐 HOST PERMISSIONS ({len(info.host_permissions)})")
            for host in info.host_permissions[:10]:
                mark = "⚠️ " if "*" in host else "  "
                print(f"   {mark}{host}")
            if len(info.host_permissions) > 10:
                print(f"   ... and {len(info.host_permissions) - 10} more")

        if info.content_scripts:
            print(f"\n📝 CONTENT SCRIPTS ({len(info.content_scripts)})")
            for cs in info.content_scripts[:5]:
                matches = cs.get("matches", [])
                print(f"   Matches: {', '.join(matches)[:50]}")

        if info.background_script:
            print(f"\n⚙️  BACKGROUND: {info.background_script}")

        patterns = self._find_interesting_patterns(info)
        if patterns:
            print(f"\n🚨 SECURITY FINDINGS ({len(patterns)})")
            for pattern in patterns[:10]:
                print(f"   {pattern}")

        print(f"\n📁 OUTPUT")
        print(f"   Folder: {folder}")
        print(f"   Files:  {len(info.files)} files")
        print(f"   Report: {folder}/report.md")
        print("=" * 60)

    def _generate_markdown_report(
        self, info: ExtensionInfo, ai_analysis: Optional[str] = None
    ) -> str:
        risk = self.manifest_analyzer.get_risk_level(info)
        zip_path = self.downloader.downloaded_zip

        md = f"""# Extension Analysis Report

## Info
- **Name:** {info.name}
- **Version:** {info.version or "Unknown"}
- **Manifest:** v{info.manifest_version or "?"}
- **Risk:** {risk}
- **Downloaded:** `{zip_path.name}`

## AI Security Analysis

{ai_analysis or "_AI analysis not available. Add OpenRouter API key to `.env` file to enable._"}

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
