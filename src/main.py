import sys
from pathlib import Path

from src.services.analyzer import ExtensionAnalyzer


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else input("Chrome Extension URL: ").strip()
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    print("\n🎯 Analyzing extension...")
    try:
        analyzer = ExtensionAnalyzer(output_dir=output_dir)
        report = analyzer.analyze_and_report(url)
        print(report)
    except Exception as e:
        print(f"❌ Error: {e}")
