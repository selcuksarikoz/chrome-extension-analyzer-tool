import os
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

from src.models.extension import ExtensionInfo


class OpenRouterAnalyzer:
    API_URL = "https://openrouter.ai/api/v1/chat/completions"
    MAX_PROMPT_CHARS = 50000
    MAX_FILE_SNIPPET = 3000

    def __init__(self, env_path: Optional[Path] = None):
        env_file = env_path or Path(".env")
        if env_file.exists():
            load_dotenv(env_file)
        else:
            load_dotenv()

        self.api_key: Optional[str] = os.getenv("OPENROUTER_API_KEY")
        self.model: str = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
        self.enabled: bool = os.getenv("OPENROUTER_ENABLED", "true").lower() in (
            "true",
            "1",
            "yes",
        )

        if not self.api_key or self.api_key.strip() in ("", "YOUR_OPENROUTER_API_KEY"):
            self.enabled = False

    def analyze_extension(self, info: ExtensionInfo) -> Optional[str]:
        if not self.enabled or not self.api_key:
            return None

        prompt = self._build_prompt(info)

        try:
            response = requests.post(
                self.API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/extension-inspector",
                    "X-Title": "Extension Inspector",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a browser extension security analyst. Analyze the provided extension code and provide a comprehensive security assessment. Focus on: 1) Overall risk level, 2) Suspicious or dangerous code patterns, 3) Data collection and exfiltration risks, 4) Network requests and external connections, 5) Permission usage analysis, 6) Specific security recommendations. Be thorough and technical.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 2000,
                },
                timeout=120,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except requests.RequestException as e:
            return f"AI analysis failed: {str(e)}"
        except (KeyError, IndexError) as e:
            return f"AI analysis parsing error: {str(e)}"

    def _build_prompt(self, info: ExtensionInfo) -> str:
        files_sample = info.files[:50] if len(info.files) > 50 else info.files

        priority_files = []
        other_files = []

        for path, content in info.file_contents.items():
            if self._is_priority_file(path):
                priority_files.append((path, content))
            else:
                other_files.append((path, content))

        all_files = priority_files + other_files

        file_patterns = []
        total_chars = 0

        for path, content in all_files:
            snippet = content[: self.MAX_FILE_SNIPPET]
            entry = f"\n--- FILE: {path} ---\n{snippet}"

            if total_chars + len(entry) > self.MAX_PROMPT_CHARS:
                file_patterns.append(
                    f"\n... ({len(all_files) - len(file_patterns)} more files truncated due to size limit)"
                )
                break

            file_patterns.append(entry)
            total_chars += len(entry)

        prompt = f"""Analyze this browser extension security:

METADATA:
- Name: {info.name}
- Version: {info.version or "Unknown"}
- Manifest: v{info.manifest_version or "Unknown"}
- Description: {info.description or "N/A"}

PERMISSIONS ({len(info.permissions)}):
{chr(10).join(f"  - {p}" for p in info.permissions) or "  None"}

HOST PERMISSIONS ({len(info.host_permissions)}):
{chr(10).join(f"  - {h}" for h in info.host_permissions[:20]) or "  None"}
{f"  ... and {len(info.host_permissions) - 20} more" if len(info.host_permissions) > 20 else ""}

CONTENT SCRIPTS: {len(info.content_scripts)}
BACKGROUND: {info.background_script or "None"}

FILES ({len(info.files)} total, {len(info.file_contents)} analyzed):
{chr(10).join(f"  - {f}" for f in files_sample)}
{chr(10) if len(info.files) > 50 else ""}{f"  ... and {len(info.files) - 50} more files" if len(info.files) > 50 else ""}

SOURCE CODE ({len(file_patterns)} files shown):
{chr(10).join(file_patterns)}
"""
        return prompt

    def _is_priority_file(self, path: str) -> bool:
        priority_names = [
            "manifest.json",
            "background",
            "content_script",
            "popup",
            "options",
            "inject",
            "main",
            "index",
        ]
        path_lower = path.lower()
        return any(p in path_lower for p in priority_names)
