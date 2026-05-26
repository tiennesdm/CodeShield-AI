/**
 * CodeShield AI - VS Code Extension
 * Main extension entry point.
 *
 * Provides:
 * - LSP client connection to CodeShield AI server
 * - Commands (Scan Now, Apply Fix, Show Details, Show Dashboard)
 * - Status bar integration
 * - Decoration providers for inline vulnerability highlighting
 * - WebView panel for vulnerability details
 */

const vscode = require("vscode");
const { CodeShieldClient } = require("./client");
const { registerCommands } = require("./commands");
const { VulnerabilityDecorations } = require("./decorations");
const { VulnerabilityWebviewProvider } = require("./webview");

// Extension state
let client = null;
let decorations = null;
let statusBarItem = null;
let outputChannel = null;
let diagnosticCollection = null;
let webviewProvider = null;

/**
 * Activate the extension.
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log("CodeShield AI extension is now active");

    // Create output channel
    outputChannel = vscode.window.createOutputChannel("CodeShield AI");
    outputChannel.appendLine("CodeShield AI Security Scanner v1.0.0");
    outputChannel.appendLine("=====================================");

    // Create diagnostic collection
    diagnosticCollection =
        vscode.languages.createDiagnosticCollection("codeshield");

    // Initialize LSP client
    client = new CodeShieldClient(context, outputChannel);
    client.start();

    // Initialize decorations
    decorations = new VulnerabilityDecorations(context);

    // Initialize webview provider
    webviewProvider = new VulnerabilityWebviewProvider(context.extensionUri);

    // Register tree data provider for security dashboard
    const treeDataProvider = new SecurityDashboardProvider();
    context.subscriptions.push(
        vscode.window.registerTreeDataProvider(
            "codeshieldSecurityDashboard",
            treeDataProvider
        )
    );

    // Register commands
    registerCommands(context, {
        client,
        decorations,
        outputChannel,
        diagnosticCollection,
        webviewProvider,
        treeDataProvider,
        refreshDashboard: () => treeDataProvider.refresh(),
    });

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Left,
        100
    );
    statusBarItem.text = "$(shield) CodeShield";
    statusBarItem.tooltip = "CodeShield AI - Click to scan current file";
    statusBarItem.command = "codeshield.scanNow";
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // Register decoration providers
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor((editor) => {
            if (editor) {
                decorations.updateDecorations(editor);
            }
        })
    );

    // Listen for diagnostics changes from LSP server
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            const config = vscode.workspace.getConfiguration("codeshield");
            if (config.get("scanOnSave", true)) {
                // Decorations will be updated when diagnostics are published
                requestScan(event.document);
            }
        })
    );

    // Listen for document save events
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration("codeshield");
            if (config.get("scanOnSave", true)) {
                requestScan(document);
            }
        })
    );

    // Listen for configuration changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration("codeshield")) {
                handleConfigurationChange();
            }
        })
    );

    // Handle LSP diagnostics
    context.subscriptions.push(
        vscode.languages.onDidChangeDiagnostics(() => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                updateDecorationsFromDiagnostics(editor);
                updateStatusBar(editor);
            }
        })
    );

    // Initial decorations
    if (vscode.window.activeTextEditor) {
        updateDecorationsFromDiagnostics(vscode.window.activeTextEditor);
    }

    // Show activation message
    vscode.window.showInformationMessage(
        "CodeShield AI is now active",
        "Scan Workspace",
        "Show Dashboard"
    ).then((selection) => {
        if (selection === "Scan Workspace") {
            vscode.commands.executeCommand("codeshield.scanWorkspace");
        } else if (selection === "Show Dashboard") {
            vscode.commands.executeCommand("codeshield.showDashboard");
        }
    });
}

/**
 * Deactivate the extension.
 */
function deactivate() {
    if (client) {
        client.stop();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
    if (outputChannel) {
        outputChannel.dispose();
    }
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}

/**
 * Request a scan for a document via LSP.
 * @param {vscode.TextDocument} document
 */
function requestScan(document) {
    if (!client) return;
    if (!isSupportedLanguage(document.languageId)) return;

    client.scanDocument(document.uri.toString());
}

/**
 * Check if a language is supported.
 * @param {string} languageId
 * @returns {boolean}
 */
function isSupportedLanguage(languageId) {
    const supported = [
        "python",
        "javascript",
        "typescript",
        "java",
        "go",
        "ruby",
        "php",
        "csharp",
        "c",
        "cpp",
        "rust",
        "swift",
        "kotlin",
        "scala",
    ];
    return supported.includes(languageId);
}

/**
 * Update decorations from current diagnostics.
 * @param {vscode.TextEditor} editor
 */
function updateDecorationsFromDiagnostics(editor) {
    const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
    const codeshieldDiagnostics = diagnostics.filter(
        (d) => d.source === "codeshield-ai"
    );

    decorations.setDecorations(editor, codeshieldDiagnostics);
}

/**
 * Update status bar with diagnostic counts.
 * @param {vscode.TextEditor} editor
 */
function updateStatusBar(editor) {
    if (!statusBarItem || !editor) return;

    const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
    const codeshieldDiagnostics = diagnostics.filter(
        (d) => d.source === "codeshield-ai"
    );

    const errors = codeshieldDiagnostics.filter(
        (d) =>
            d.severity === vscode.DiagnosticSeverity.Error ||
            d.severity === vscode.DiagnosticSeverity.Warning
    ).length;

    if (codeshieldDiagnostics.length === 0) {
        statusBarItem.text = "$(shield) CodeShield";
        statusBarItem.backgroundColor = undefined;
    } else if (errors > 0) {
        statusBarItem.text = `$(shield) ${codeshieldDiagnostics.length} issues`;
        statusBarItem.backgroundColor = new vscode.ThemeColor(
            "statusBarItem.warningBackground"
        );
    } else {
        statusBarItem.text = `$(shield) ${codeshieldDiagnostics.length} issues`;
        statusBarItem.backgroundColor = undefined;
    }

    statusBarItem.tooltip = `CodeShield AI: ${codeshieldDiagnostics.length} security issues found`;
}

/**
 * Handle configuration changes.
 */
function handleConfigurationChange() {
    const config = vscode.workspace.getConfiguration("codeshield");
    const enabled = config.get("enabled", true);

    if (enabled) {
        if (!statusBarItem) {
            statusBarItem = vscode.window.createStatusBarItem(
                vscode.StatusBarAlignment.Left,
                100
            );
        }
        statusBarItem.show();
    } else {
        if (statusBarItem) {
            statusBarItem.hide();
        }
    }

    outputChannel?.appendLine("Configuration updated");
}

/**
 * Security Dashboard Tree Data Provider.
 */
class SecurityDashboardProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.vulnerabilities = [];
        this.stats = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            total: 0,
        };
    }

    refresh() {
        this._updateStats();
        this._onDidChangeTreeData.fire();
    }

    setVulnerabilities(vulns) {
        this.vulnerabilities = vulns;
        this._updateStats();
        this._onDidChangeTreeData.fire();
    }

    _updateStats() {
        this.stats = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            total: this.vulnerabilities.length,
        };
        for (const v of this.vulnerabilities) {
            const sev = (v.severity || "LOW").toUpperCase();
            if (sev in this.stats) {
                this.stats[sev]++;
            }
        }
    }

    getTreeItem(element) {
        return element;
    }

    getChildren(element) {
        if (!element) {
            // Root items: summary stats
            const items = [
                new DashboardItem(
                    `Total Issues: ${this.stats.total}`,
                    "",
                    vscode.TreeItemCollapsibleState.None,
                    "$(shield)"
                ),
            ];

            if (this.stats.critical > 0) {
                items.push(
                    new DashboardItem(
                        `Critical: ${this.stats.critical}`,
                        "Click to filter",
                        vscode.TreeItemCollapsibleState.Collapsed,
                        "$(error)"
                    )
                );
            }
            if (this.stats.high > 0) {
                items.push(
                    new DashboardItem(
                        `High: ${this.stats.high}`,
                        "Click to filter",
                        vscode.TreeItemCollapsibleState.Collapsed,
                        "$(warning)"
                    )
                );
            }
            if (this.stats.medium > 0) {
                items.push(
                    new DashboardItem(
                        `Medium: ${this.stats.medium}`,
                        "Click to filter",
                        vscode.TreeItemCollapsibleState.Collapsed,
                        "$(info)"
                    )
                );
            }
            if (this.stats.low > 0) {
                items.push(
                    new DashboardItem(
                        `Low: ${this.stats.low}`,
                        "Click to filter",
                        vscode.TreeItemCollapsibleState.Collapsed,
                        "$(pass)"
                    )
                );
            }

            if (this.vulnerabilities.length === 0) {
                items.push(
                    new DashboardItem(
                        "No issues found ✓",
                        "Your code looks secure!",
                        vscode.TreeItemCollapsibleState.None,
                        "$(check)"
                    )
                );
            }

            return items;
        }

        // Child items: vulnerabilities by severity
        const severity = element.label.split(":")[0].toUpperCase();
        return this.vulnerabilities
            .filter((v) => (v.severity || "").toUpperCase() === severity)
            .map(
                (v) =>
                    new DashboardItem(
                        v.title || v.category || "Unknown",
                        `${v.file_path || ""}:${v.line_number || ""}`,
                        vscode.TreeItemCollapsibleState.None,
                        undefined,
                        {
                            command: "codeshield.showDetails",
                            title: "Show Details",
                            arguments: [v],
                        }
                    )
            );
    }
}

/**
 * Dashboard tree item.
 */
class DashboardItem extends vscode.TreeItem {
    constructor(label, description, collapsibleState, iconPath, command) {
        super(label, collapsibleState);
        this.description = description;
        if (iconPath) {
            this.iconPath = new vscode.ThemeIcon(iconPath.replace(/\$\(|\)/g, ""));
        }
        if (command) {
            this.command = command;
        }
        this.contextValue = "vulnerability";
    }
}

module.exports = {
    activate,
    deactivate,
};
