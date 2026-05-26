/**
 * CodeShield AI - VS Code Extension Commands
 *
 * Registers all extension commands:
 * - codeshield.scanNow: Scan current document
 * - codeshield.scanWorkspace: Scan entire workspace
 * - codeshield.applyFix: Apply security fix
 * - codeshield.showDetails: Show vulnerability details
 * - codeshield.showDashboard: Show security dashboard
 * - codeshield.clearDiagnostics: Clear all diagnostics
 * - codeshield.toggleEnabled: Toggle extension on/off
 * - codeshield.openSettings: Open settings page
 */

const vscode = require("vscode");

/**
 * Register all extension commands.
 * @param {vscode.ExtensionContext} context
 * @param {Object} deps - Dependencies (client, decorations, outputChannel, etc.)
 */
function registerCommands(context, deps) {
    const {
        client,
        decorations,
        outputChannel,
        diagnosticCollection,
        webviewProvider,
        treeDataProvider,
        refreshDashboard,
    } = deps;

    // Scan Now - Scan current document
    context.subscriptions.push(
        vscode.commands.registerCommand("codeshield.scanNow", async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage(
                    "No active editor to scan"
                );
                return;
            }

            const document = editor.document;
            outputChannel.appendLine(`🔍 Scanning: ${document.fileName}`);

            // Show progress
            await vscode.window.withProgress(
                {
                    location: vscode.ProgressLocation.Notification,
                    title: `CodeShield: Scanning ${document.fileName.split("/").pop()}...`,
                    cancellable: false,
                },
                async (progress) => {
                    progress.report({ increment: 0 });

                    // Request scan via LSP client
                    if (client && client.isReady) {
                        client.scanDocument(document.uri.toString());
                    } else {
                        // Fallback: perform local analysis
                        await performLocalScan(document, diagnosticCollection);
                    }

                    progress.report({ increment: 100 });
                    await new Promise((resolve) => setTimeout(resolve, 1000));
                }
            );

            // Update dashboard
            const diagnostics = vscode.languages.getDiagnostics(document.uri);
            const vulnDiagnostics = diagnostics.filter(
                (d) => d.source === "codeshield-ai"
            );

            const vulns = vulnDiagnostics.map((d) => ({
                title: d.message.split(":")[0].replace(/\[.*?\]\s*/, ""),
                severity:
                    d.severity === vscode.DiagnosticSeverity.Error
                        ? "CRITICAL"
                        : d.severity === vscode.DiagnosticSeverity.Warning
                            ? "HIGH"
                            : "MEDIUM",
                file_path: document.fileName,
                line_number: d.range.start.line + 1,
                category: d.code || "Security",
                description: d.message,
            }));

            treeDataProvider.setVulnerabilities(vulns);

            const msg =
                vulnDiagnostics.length === 0
                    ? "✅ No security issues found"
                    : `⚠️ Found ${vulnDiagnostics.length} security issues`;
            vscode.window.showInformationMessage(msg, "Show Details").then(
                (sel) => {
                    if (sel === "Show Details") {
                        vscode.commands.executeCommand(
                            "codeshield.showDashboard"
                        );
                    }
                }
            );
        })
    );

    // Scan Workspace - Scan all files in workspace
    context.subscriptions.push(
        vscode.commands.registerCommand(
            "codeshield.scanWorkspace",
            async () => {
                outputChannel.appendLine("🔍 Starting workspace scan...");

                const config = vscode.workspace.getConfiguration("codeshield");
                if (!config.get("enabled", true)) {
                    vscode.window.showWarningMessage(
                        "CodeShield is disabled. Enable it in settings."
                    );
                    return;
                }

                await vscode.window.withProgress(
                    {
                        location: vscode.ProgressLocation.Notification,
                        title: "CodeShield: Scanning workspace...",
                        cancellable: true,
                    },
                    async (progress, token) => {
                        const files = await vscode.workspace.findFiles(
                            "**/*.{py,js,ts,java,go,rb,php,cs,c,cpp,rs,swift,kt}",
                            "**/node_modules/**,**/.venv/**,**/vendor/**,**/build/**,**/dist/**"
                        );

                        const total = files.length;
                        let scanned = 0;
                        let totalIssues = 0;

                        for (const file of files) {
                            if (token.isCancellationRequested) break;

                            try {
                                const document =
                                    await vscode.workspace.openTextDocument(file);

                                if (client && client.isReady) {
                                    client.scanDocument(file.toString());
                                } else {
                                    const count = await performLocalScan(
                                        document,
                                        diagnosticCollection
                                    );
                                    totalIssues += count;
                                }

                                scanned++;
                                progress.report({
                                    increment: 100 / total,
                                    message: `${scanned}/${total} files (${totalIssues} issues)`,
                                });
                            } catch (e) {
                                // Skip files that can't be opened
                            }
                        }

                        outputChannel.appendLine(
                            `Workspace scan complete: ${scanned} files scanned, ${totalIssues} issues found`
                        );

                        vscode.window.showInformationMessage(
                            `CodeShield: ${scanned} files scanned, ${totalIssues} issues found`,
                            "Show Dashboard"
                        ).then((sel) => {
                            if (sel === "Show Dashboard") {
                                vscode.commands.executeCommand(
                                    "codeshield.showDashboard"
                                );
                            }
                        });
                    }
                );

                refreshDashboard();
            }
        )
    );

    // Apply Fix - Apply security fix at cursor position
    context.subscriptions.push(
        vscode.commands.registerCommand(
            "codeshield.applyFix",
            async (args) => {
                const editor = vscode.window.activeTextEditor;
                if (!editor) return;

                const position = editor.selection.active;
                const document = editor.document;
                const diagnostics = vscode.languages.getDiagnostics(document.uri);

                // Find diagnostic at cursor position
                const diagnostic = diagnostics.find(
                    (d) =>
                        d.source === "codeshield-ai" &&
                        d.range.contains(position)
                );

                if (!diagnostic) {
                    vscode.window.showInformationMessage(
                        "No vulnerability found at cursor position"
                    );
                    return;
                }

                // Extract fix suggestion from diagnostic data
                const fixSuggestion =
                    diagnostic.data?.fix_suggestion ||
                    "// FIXME: Review and fix this security issue";

                // Apply the fix
                await editor.edit((editBuilder) => {
                    // Add fix as a comment above the problematic line
                    const line = document.lineAt(diagnostic.range.start.line);
                    const indentation = line.text.match(/^\s*/)[0];
                    const fixText = `${indentation}// SECURITY FIX: ${fixSuggestion}\n`;

                    editBuilder.insert(line.range.start, fixText);
                });

                vscode.window.showInformationMessage(
                    "🔧 Fix suggestion applied as comment. Review and apply the actual fix."
                );

                outputChannel.appendLine(
                    `Applied fix for: ${diagnostic.message}`
                );
            }
        )
    );

    // Show Details - Show vulnerability details in webview
    context.subscriptions.push(
        vscode.commands.registerCommand(
            "codeshield.showDetails",
            async (vulnerability) => {
                if (!vulnerability) {
                    const editor = vscode.window.activeTextEditor;
                    if (!editor) return;

                    const position = editor.selection.active;
                    const diagnostics = vscode.languages.getDiagnostics(
                        editor.document.uri
                    );
                    const diagnostic = diagnostics.find(
                        (d) =>
                            d.source === "codeshield-ai" &&
                            d.range.contains(position)
                    );

                    if (!diagnostic) {
                        vscode.window.showInformationMessage(
                            "No vulnerability at cursor position"
                        );
                        return;
                    }

                    vulnerability = {
                        title:
                            diagnostic.message.split(":")[0] ||
                            "Security Vulnerability",
                        severity:
                            diagnostic.severity ===
                                vscode.DiagnosticSeverity.Error
                                ? "CRITICAL"
                                : "HIGH",
                        category: diagnostic.code || "Security",
                        description: diagnostic.message,
                        file_path: editor.document.fileName,
                        line_number: diagnostic.range.start.line + 1,
                        cwe_id: diagnostic.data?.cwe_id || "N/A",
                        fix_suggestion:
                            diagnostic.data?.fix_suggestion ||
                            "Review and fix based on CWE guidelines.",
                        code_snippet: editor.document.lineAt(
                            diagnostic.range.start.line
                        ).text,
                    };
                }

                webviewProvider.showVulnerability(vulnerability);
            }
        )
    );

    // Show Dashboard
    context.subscriptions.push(
        vscode.commands.registerCommand(
            "codeshield.showDashboard",
            () => {
                vscode.commands.executeCommand(
                    "codeshieldSecurityDashboard.focus"
                );
            }
        )
    );

    // Clear Diagnostics
    context.subscriptions.push(
        vscode.commands.registerCommand(
            "codeshield.clearDiagnostics",
            () => {
                diagnosticCollection.clear();

                // Also clear LSP diagnostics
                vscode.workspace.textDocuments.forEach((doc) => {
                    // LSP diagnostics are managed by the server, but we can request a clear
                });

                vscode.window.showInformationMessage(
                    "All security diagnostics cleared"
                );
                outputChannel.appendLine("Diagnostics cleared");
                refreshDashboard();
            }
        )
    );

    // Toggle Enabled
    context.subscriptions.push(
        vscode.commands.registerCommand(
            "codeshield.toggleEnabled",
            async () => {
                const config = vscode.workspace.getConfiguration("codeshield");
                const current = config.get("enabled", true);
                await config.update("enabled", !current, true);

                vscode.window.showInformationMessage(
                    `CodeShield AI ${!current ? "enabled" : "disabled"}`
                );
            }
        )
    );

    // Open Settings
    context.subscriptions.push(
        vscode.commands.registerCommand("codeshield.openSettings", () => {
            vscode.commands.executeCommand(
                "workbench.action.openSettings",
                "codeshield"
            );
        })
    );
}

/**
 * Perform a local-only security scan (fallback when LSP server is unavailable).
 * @param {vscode.TextDocument} document
 * @param {vscode.DiagnosticCollection} diagnosticCollection
 * @returns {number} Number of issues found
 */
async function performLocalScan(document, diagnosticCollection) {
    const content = document.getText();
    const lines = content.split("\n");
    const diagnostics = [];

    // Simple pattern-based scanning
    const patterns = [
        {
            regex: /password\s*=\s*["'][^"']+["']/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: "[HIGH] Hardcoded password detected. Use environment variables.",
            code: "CWE-798",
        },
        {
            regex: /api[_-]?key\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: "[HIGH] Hardcoded API key detected. Use environment variables.",
            code: "CWE-798",
        },
        {
            regex: /eval\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: "[HIGH] Dangerous eval() usage. Can lead to code injection.",
            code: "CWE-94",
        },
        {
            regex: /\.execute\s*\(\s*[`"'].*\$/gi,
            severity: vscode.DiagnosticSeverity.Error,
            message: "[CRITICAL] Possible SQL injection. Use parameterized queries.",
            code: "CWE-89",
        },
        {
            regex: /http:\/\/[^\s"']+/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: "[MEDIUM] HTTP (non-HTTPS) URL detected. Use HTTPS.",
            code: "CWE-319",
        },
        {
            regex: /innerHTML\s*=/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: "[HIGH] innerHTML assignment can lead to XSS. Use textContent.",
            code: "CWE-79",
        },
        {
            regex: /debug\s*=\s*true/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: "[MEDIUM] Debug mode enabled. Should be False in production.",
            code: "CWE-489",
        },
        {
            regex: /hashlib\.md5\s*\(/gi,
            severity: vscode.DiagnosticSeverity.Warning,
            message: "[MEDIUM] Weak MD5 hash. Use SHA-256 for security operations.",
            code: "CWE-328",
        },
    ];

    for (const patternDef of patterns) {
        let match;
        const regex = new RegExp(patternDef.regex.source, "gi");
        while ((match = regex.exec(content)) !== null) {
            const lineNum = content.substring(0, match.index).split("\n").length - 1;
            const line = lines[lineNum];
            const startChar = match.index - content.lastIndexOf("\n", match.index) - 1;

            const range = new vscode.Range(
                new vscode.Position(lineNum, Math.max(0, startChar)),
                new vscode.Position(lineNum, startChar + match[0].length)
            );

            const diagnostic = new vscode.Diagnostic(
                range,
                patternDef.message,
                patternDef.severity
            );
            diagnostic.code = patternDef.code;
            diagnostic.source = "codeshield-ai";
            diagnostics.push(diagnostic);
        }
    }

    diagnosticCollection.set(document.uri, diagnostics);
    return diagnostics.length;
}

module.exports = {
    registerCommands,
};
