# CodeShield AI - VS Code Extension

Real-time security vulnerability detection and fixing for your code.

## Features

- **On-save scanning**: Automatically scans your code for security vulnerabilities when you save
- **Multi-language support**: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, C/C++, Rust, Swift, Kotlin
- **Inline highlighting**: Visual decorations show vulnerabilities directly in your editor
- **Hover details**: Hover over any highlighted line to see vulnerability details
- **Quick fixes**: Apply suggested fixes with a single click
- **Security dashboard**: Overview of all security issues in your workspace
- **LSP integration**: Full Language Server Protocol support for advanced features

## Supported Vulnerability Types

| Category | Severity | Languages |
|----------|----------|-----------|
| SQL Injection | CRITICAL | Python, Java, JavaScript, Go |
| Hardcoded Secrets | HIGH | All |
| XSS | HIGH | JavaScript, TypeScript |
| Command Injection | HIGH | Python, Go |
| Insecure Deserialization | HIGH | Python, Java |
| SSTI | CRITICAL | Python |
| Weak Cryptography | MEDIUM | All |
| Insecure Protocols (HTTP) | MEDIUM | All |
| Debug Mode Enabled | MEDIUM | Python |

## Installation

### From VS Code Marketplace

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "CodeShield AI"
4. Click Install

### From Source

```bash
cd vscode_extension
npm install
npm run compile
# Press F5 to launch the extension in a new Extension Development Host
```

## Configuration

Open VS Code settings (Ctrl+,) and search for "codeshield":

| Setting | Default | Description |
|---------|---------|-------------|
| `codeshield.enabled` | `true` | Enable/disable scanning |
| `codeshield.scanOnSave` | `true` | Scan when files are saved |
| `codeshield.severityThreshold` | `LOW` | Minimum severity to report |
| `codeshield.maxDiagnosticsPerFile` | `50` | Max issues shown per file |
| `codeshield.enableCodeActions` | `true` | Enable quick fixes |
| `codeshield.enableHover` | `true` | Enable hover information |
| `codeshield.showInlineDecorations` | `true` | Show inline highlights |
| `codeshield.ignorePatterns` | `["test_*", ...]` | Files/paths to ignore |

## Commands

| Command | Keybinding | Description |
|---------|-----------|-------------|
| `CodeShield: Scan Now` | Ctrl+Shift+S | Scan the current file |
| `CodeShield: Scan Workspace` | - | Scan all files in workspace |
| `CodeShield: Apply Security Fix` | - | Apply fix at cursor |
| `CodeShield: Show Details` | - | Show vulnerability details |
| `CodeShield: Show Dashboard` | Ctrl+Shift+D | Open security dashboard |
| `CodeShield: Clear Diagnostics` | - | Clear all diagnostics |
| `CodeShield: Toggle CodeShield` | - | Enable/disable extension |

## Security Dashboard

The Security Dashboard shows:
- Total vulnerability count by severity
- Per-file breakdown
- Quick navigation to each issue
- Scan status

## Requirements

- VS Code 1.85+
- Python 3.10+ (for LSP server)
- CodeShield AI API token (optional, for advanced features)

## License

MIT
