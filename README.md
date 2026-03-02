# Extension Inspector

Chrome extension analyzer tool that extracts and analyzes Chrome Web Store extensions.

## Features

- Analyze Chrome extensions from Web Store URLs
- Extract extension metadata, permissions, and resources
- Download and inspect extension files

## Installation

```bash
uv sync
```

## Usage

```bash
uv run inspect "https://chrome.google.com/webstore/detail/..."

# With custom output directory:
uv run inspect "https://chrome.google.com/webstore/detail/..." ./output-folder
```

## Development

```bash
uv run pytest      # Run tests
uv run ruff check  # Lint code
```
