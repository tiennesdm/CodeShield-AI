/**
 * CodeShield AI - LSP Client Connection
 *
 * Manages the connection to the CodeShield AI Language Server.
 * Handles server lifecycle, communication, and diagnostic updates.
 */

const vscode = require("vscode");
const {
    LanguageClient,
    TransportKind,
} = require("vscode-languageclient");

class CodeShieldClient {
    /**
     * @param {vscode.ExtensionContext} context
     * @param {vscode.OutputChannel} outputChannel
     */
    constructor(context, outputChannel) {
        this.context = context;
        this.outputChannel = outputChannel;
        this.client = null;
        this.isReady = false;
    }

    /**
     * Start the LSP client and server.
     */
    start() {
        const config = vscode.workspace.getConfiguration("codeshield");
        const serverPort = config.get("lspServer.port", 8211);
        const apiUrl = config.get("apiUrl", "https://api.codeshield.ai");
        const apiToken = config.get("apiToken", "");

        const serverOptions = {
            command: "python3",
            args: [
                "-m",
                "codeshield.lsp_server",
                "--stdio",
            ],
            options: {
                cwd: vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath,
                env: {
                    ...process.env,
                    CODESHIELD_API_URL: apiUrl,
                    CODESHIELD_API_TOKEN: apiToken,
                },
            },
        };

        // Fallback to TCP if stdio server not available
        const tcpServerOptions = () => {
            return new Promise((resolve, reject) => {
                const net = require("net");
                const socket = new net.Socket();
                socket.connect(serverPort, "127.0.0.1", () => {
                    resolve({
                        reader: socket,
                        writer: socket,
                    });
                });
                socket.on("error", (err) => {
                    this.outputChannel.appendLine(
                        `TCP connection failed: ${err.message}`
                    );
                    // Fall back to built-in local mode
                    reject(err);
                });
            });
        };

        const clientOptions = {
            documentSelector: [
                { scheme: "file", language: "python" },
                { scheme: "file", language: "javascript" },
                { scheme: "file", language: "typescript" },
                { scheme: "file", language: "java" },
                { scheme: "file", language: "go" },
                { scheme: "file", language: "ruby" },
                { scheme: "file", language: "php" },
                { scheme: "file", language: "csharp" },
                { scheme: "file", language: "c" },
                { scheme: "file", language: "cpp" },
                { scheme: "file", language: "rust" },
                { scheme: "file", language: "swift" },
                { scheme: "file", language: "kotlin" },
            ],
            synchronize: {
                fileEvents: vscode.workspace.createFileSystemWatcher("**/*"),
                configurationSection: "codeshield",
            },
            outputChannel: this.outputChannel,
            revealOutputChannelOn: 1, // Never
            initializationOptions: {
                apiUrl,
                apiToken,
                severityThreshold: config.get("severityThreshold", "LOW"),
                enabledTools: config.get("enabledTools", [
                    "semgrep",
                    "bandit",
                    "eslint",
                    "custom_ai",
                ]),
                scanOnSave: config.get("scanOnSave", true),
                maxDiagnosticsPerFile: config.get("maxDiagnosticsPerFile", 50),
                enableCodeActions: config.get("enableCodeActions", true),
                enableHover: config.get("enableHover", true),
                ignorePatterns: config.get("ignorePatterns", []),
            },
            middleware: {
                provideDiagnostics: (uri, previousResult, token, next) => {
                    return next(uri, previousResult, token);
                },
                handleDiagnostics: (uri, diagnostics, next) => {
                    // Enhance diagnostics with CodeShield-specific data
                    const enhancedDiagnostics = diagnostics.map((d) => {
                        if (d.source === "codeshield-ai" && d.data) {
                            d.code = d.data.cwe_id || d.code;
                        }
                        return d;
                    });
                    next(uri, enhancedDiagnostics);
                },
            },
        };

        this.client = new LanguageClient(
            "codeshield-ai",
            "CodeShield AI Security Scanner",
            serverOptions,
            clientOptions
        );

        // Handle connection events
        this.client.onReady().then(() => {
            this.isReady = true;
            this.outputChannel.appendLine(
                "✅ Connected to CodeShield AI language server"
            );

            // Notify user
            vscode.window.setStatusBarMessage(
                "$(shield) CodeShield AI connected",
                5000
            );

            // Register for configuration changes
            this.client.onNotification(
                "codeshield/configurationChanged",
                (params) => {
                    this.outputChannel.appendLine(
                        `Configuration changed: ${JSON.stringify(params)}`
                    );
                }
            );

            // Handle scan status notifications
            this.client.onNotification("codeshield/scanStatus", (params) => {
                this.handleScanStatus(params);
            });
        });

        this.client.start().catch((err) => {
            this.outputChannel.appendLine(
                `⚠️ LSP client start warning: ${err.message}`
            );
            this.outputChannel.appendLine(
                "Falling back to local-only security scanning"
            );
            this.isReady = false;
        });
    }

    /**
     * Handle scan status notifications from the server.
     * @param {Object} params
     */
    handleScanStatus(params) {
        const { status, file, vulnerabilities } = params;

        switch (status) {
            case "started":
                this.outputChannel.appendLine(`🔍 Scanning: ${file}`);
                break;
            case "completed":
                this.outputChannel.appendLine(
                    `✅ Scan complete: ${file} - ${vulnerabilities || 0} issues`
                );
                break;
            case "failed":
                this.outputChannel.appendLine(`❌ Scan failed: ${file}`);
                break;
        }
    }

    /**
     * Request a scan for a specific document.
     * @param {string} uri Document URI
     */
    scanDocument(uri) {
        if (!this.isReady || !this.client) return;

        this.client.sendNotification("codeshield/scanNow", { uri });
    }

    /**
     * Get server status.
     * @returns {Object}
     */
    getStatus() {
        return {
            connected: this.isReady,
            clientState: this.client?.state || "stopped",
        };
    }

    /**
     * Stop the client.
     */
    stop() {
        if (this.client) {
            this.client.stop();
            this.isReady = false;
        }
    }
}

module.exports = {
    CodeShieldClient,
};
