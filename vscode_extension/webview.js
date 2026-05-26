/**
 * CodeShield AI - Vulnerability Detail WebView Panel
 *
 * Provides a rich WebView panel for viewing vulnerability details:
 * - Full vulnerability description
 * - CWE information with links
 * - Code snippet with syntax highlighting
 * - Fix suggestion with copy button
 * - Severity visualization
 */

const vscode = require("vscode");

class VulnerabilityWebviewProvider {
    /**
     * @param {vscode.Uri} extensionUri
     */
    constructor(extensionUri) {
        this.extensionUri = extensionUri;
        this.panel = null;
    }

    /**
     * Show vulnerability details in a WebView panel.
     * @param {Object} vulnerability
     */
    showVulnerability(vulnerability) {
        const v = vulnerability;

        // Create or reveal panel
        if (!this.panel) {
            this.panel = vscode.window.createWebviewPanel(
                "codeshieldVulnerability",
                "Vulnerability Details",
                vscode.ViewColumn.Two,
                {
                    enableScripts: true,
                    retainContextWhenHidden: true,
                    localResourceRoots: [this.extensionUri],
                }
            );

            this.panel.onDidDispose(() => {
                this.panel = null;
            });
        }

        this.panel.title = `${v.severity || "INFO"}: ${v.title || "Vulnerability"}`;
        this.panel.webview.html = this._getWebviewContent(v);
    }

    /**
     * Generate WebView HTML content for a vulnerability.
     * @param {Object} v
     * @returns {string}
     */
    _getWebviewContent(v) {
        const severity = (v.severity || "INFO").toUpperCase();
        const severityColors = {
            CRITICAL: { bg: "#DC2626", text: "#FEE2E2", label: "Critical" },
            HIGH: { bg: "#EA580C", text: "#FFEDD5", label: "High" },
            MEDIUM: { bg: "#D97706", text: "#FEF3C7", label: "Medium" },
            LOW: { bg: "#65A30D", text: "#ECFCCB", label: "Low" },
            INFO: { bg: "#2563EB", text: "#DBEAFE", label: "Info" },
        };
        const colors = severityColors[severity] || severityColors.INFO;

        const cweLink = v.cwe_id
            ? `https://cwe.mitre.org/data/definitions/${v.cwe_id.replace("CWE-", "")}.html`
            : "#";

        const escapeHtml = (str) => {
            if (!str) return "";
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        };

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeShield - Vulnerability Details</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            padding: 20px;
            background: var(--vscode-editor-background, #1e1e1e);
            color: var(--vscode-editor-foreground, #d4d4d4);
            line-height: 1.6;
        }
        .header {
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--vscode-panel-border, #333);
        }
        .severity-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
            background-color: ${colors.bg};
            color: ${colors.text};
        }
        .title {
            font-size: 22px;
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--vscode-editor-foreground, #d4d4d4);
        }
        .meta {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            font-size: 13px;
            color: var(--vscode-descriptionForeground, #808080);
        }
        .meta-item {
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .meta-item a {
            color: var(--vscode-textLink-foreground, #3794ff);
            text-decoration: none;
        }
        .meta-item a:hover {
            text-decoration: underline;
        }
        .section {
            margin-bottom: 24px;
        }
        .section-title {
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--vscode-descriptionForeground, #808080);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .section-content {
            font-size: 14px;
            line-height: 1.7;
            padding: 12px;
            background: var(--vscode-textBlockQuote-background, #2a2d2e);
            border-radius: 6px;
            border-left: 3px solid var(--vscode-textBlockQuote-border, #007acc);
        }
        .code-block {
            position: relative;
            background: var(--vscode-textCodeBlock-background, #1a1a1a);
            border: 1px solid var(--vscode-panel-border, #333);
            border-radius: 6px;
            padding: 16px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .code-block .language {
            position: absolute;
            top: 4px;
            right: 8px;
            font-size: 11px;
            color: var(--vscode-descriptionForeground, #808080);
        }
        .copy-btn {
            position: absolute;
            top: 4px;
            right: 60px;
            padding: 2px 8px;
            font-size: 11px;
            background: var(--vscode-button-background, #0e639c);
            color: var(--vscode-button-foreground, #fff);
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .copy-btn:hover {
            background: var(--vscode-button-hoverBackground, #1177bb);
        }
        .fix-section {
            background: rgba(22, 163, 74, 0.1);
            border-left-color: #16a34a;
        }
        .fix-section .section-content {
            background: rgba(22, 163, 74, 0.05);
            border-left-color: #16a34a;
        }
        .actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid var(--vscode-panel-border, #333);
        }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover {
            opacity: 0.85;
        }
        .btn-primary {
            background: var(--vscode-button-background, #0e639c);
            color: var(--vscode-button-foreground, #fff);
        }
        .btn-secondary {
            background: var(--vscode-button-secondaryBackground, #3c3c3c);
            color: var(--vscode-button-secondaryForeground, #ccc);
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 10px;
            margin-bottom: 20px;
        }
        .stat-card {
            padding: 12px;
            background: var(--vscode-textBlockQuote-background, #2a2d2e);
            border-radius: 6px;
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: 700;
        }
        .stat-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--vscode-descriptionForeground, #808080);
            margin-top: 4px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="severity-badge">${colors.label}</div>
        <h1 class="title">${escapeHtml(v.title || "Unknown Vulnerability")}</h1>
        <div class="meta">
            <div class="meta-item">
                <span>📁</span>
                <span>${escapeHtml(v.file_path || "Unknown")}</span>
            </div>
            <div class="meta-item">
                <span>📍</span>
                <span>Line ${v.line_number || "?"}${v.column ? `, Col ${v.column}` : ""}</span>
            </div>
            <div class="meta-item">
                <span>🏷️</span>
                <span>${escapeHtml(v.category || "General")}</span>
            </div>
            <div class="meta-item">
                <span>🔗</span>
                <a href="${cweLink}" target="_blank">${escapeHtml(v.cwe_id || "N/A")}</a>
            </div>
            ${v.cwe_name ? `<div class="meta-item"><span>📋</span><span>${escapeHtml(v.cwe_name)}</span></div>` : ""}
            ${v.cvss_score ? `<div class="meta-item"><span>📊</span><span>CVSS: ${v.cvss_score}</span></div>` : ""}
        </div>
    </div>

    <div class="section">
        <div class="section-title">📝 Description</div>
        <div class="section-content">
            ${escapeHtml(v.description || "No description available.")}
        </div>
    </div>

    ${v.code_snippet ? `
    <div class="section">
        <div class="section-title">🔍 Affected Code</div>
        <div class="code-block">
            <span class="language">source</span>
            <button class="copy-btn" onclick="copyCode(this)">Copy</button>
            ${escapeHtml(v.code_snippet)}
        </div>
    </div>
    ` : ""}

    ${v.fix_suggestion ? `
    <div class="section fix-section">
        <div class="section-title">🔧 Suggested Fix</div>
        <div class="section-content">
            ${escapeHtml(v.fix_suggestion)}
        </div>
    </div>
    ` : ""}

    ${v.tool_source ? `
    <div class="section">
        <div class="section-title">🔬 Detection</div>
        <div class="section-content">
            Detected by: <strong>${escapeHtml(v.tool_source)}</strong>
            ${v.confidence ? `<br>Confidence: <strong>${v.confidence}</strong>` : ""}
        </div>
    </div>
    ` : ""}

    <div class="actions">
        <button class="btn btn-primary" onclick="applyFix()">Apply Fix</button>
        <button class="btn btn-secondary" onclick="ignoreFinding()">Ignore</button>
        <button class="btn btn-secondary" onclick="copyDetails()">Copy Details</button>
    </div>

    <script>
        const vscode = acquireVsCodeApi();

        function applyFix() {
            vscode.postMessage({ command: 'applyFix' });
        }

        function ignoreFinding() {
            vscode.postMessage({ command: 'ignore' });
        }

        function copyDetails() {
            const details = document.body.innerText;
            navigator.clipboard.writeText(details).then(() => {
                const btn = document.querySelector('.btn-secondary:last-child');
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = 'Copy Details', 2000);
            });
        }

        function copyCode(btn) {
            const code = btn.parentElement.innerText.replace('Copy', '').replace(/\\n\\s*$/g, '');
            navigator.clipboard.writeText(code).then(() => {
                btn.textContent = 'Copied!';
                setTimeout(() => btn.textContent = 'Copy', 2000);
            });
        }

        // Handle messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.command) {
                case 'update':
                    // Update content dynamically
                    break;
            }
        });
    </script>
</body>
</html>`;
    }

    /**
     * Dispose the panel.
     */
    dispose() {
        if (this.panel) {
            this.panel.dispose();
            this.panel = null;
        }
    }
}

module.exports = {
    VulnerabilityWebviewProvider,
};
