# Extension Inspector

Chrome extension analyzer tool that extracts and analyzes Chrome Web Store extensions.

## Features

- Analyze Chrome extensions from Web Store URLs
- Extract extension metadata, permissions, and resources
- Download and inspect extension files
- AI-powered security analysis via OpenRouter

## Installation

```bash
uv sync
```

## Configuration

Copy `.env.example` to `.env` and add your OpenRouter API key:

```bash
cp .env.example .env
```

Edit `.env`:

```
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=arcee-ai/trinity-large-preview:free
OPENROUTER_ENABLED=true
```

Get your API key from [OpenRouter](https://openrouter.ai/keys).

## Usage

```bash
uv run inspect "https://chrome.google.com/webstore/detail/..."

# With custom output directory:
uv run inspect "https://chrome.google.com/webstore/detail/..." ./output-folder
```

The tool generates a `report.md` with:

- Extension metadata and permissions
- AI security analysis (if configured)
- File structure and code findings

## Development

```bash
uv run pytest      # Run tests
uv run ruff check  # Lint code
```
