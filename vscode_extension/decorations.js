/**
 * CodeShield AI - Inline Vulnerability Highlighting
 *
 * Provides visual decorations for security vulnerabilities in the editor:
 * - Underlines for vulnerable code lines
 * - Gutter icons showing severity
 * - Overview ruler markers
 * - Inline message annotations
 */

const vscode = require("vscode");

class VulnerabilityDecorations {
    /**
     * @param {vscode.ExtensionContext} context
     */
    constructor(context) {
        this.context = context;

        // Create decoration types for each severity level
        this.decorationTypes = {
            critical: vscode.window.createTextEditorDecorationType({
                isWholeLine: true,
                backgroundColor: "rgba(220, 38, 38, 0.15)",
                borderWidth: "0 0 1px 0",
                borderColor: "rgba(220, 38, 38, 0.8)",
                borderStyle: "solid",
                overviewRulerColor: "rgba(220, 38, 38, 0.8)",
                overviewRulerLane: vscode.OverviewRulerLane.Right,
                gutterIconPath: this._createGutterIcon("critical"),
                gutterIconSize: "contain",
                after: {
                    color: "rgba(220, 38, 38, 0.7)",
                    fontStyle: "italic",
                },
            }),
            high: vscode.window.createTextEditorDecorationType({
                isWholeLine: true,
                backgroundColor: "rgba(234, 88, 12, 0.12)",
                borderWidth: "0 0 1px 0",
                borderColor: "rgba(234, 88, 12, 0.7)",
                borderStyle: "solid",
                overviewRulerColor: "rgba(234, 88, 12, 0.7)",
                overviewRulerLane: vscode.OverviewRulerLane.Right,
                gutterIconPath: this._createGutterIcon("high"),
                gutterIconSize: "contain",
                after: {
                    color: "rgba(234, 88, 12, 0.6)",
                    fontStyle: "italic",
                },
            }),
            medium: vscode.window.createTextEditorDecorationType({
                isWholeLine: true,
                backgroundColor: "rgba(217, 119, 6, 0.1)",
                borderWidth: "0 0 1px 0",
                borderColor: "rgba(217, 119, 6, 0.6)",
                borderStyle: "dashed",
                overviewRulerColor: "rgba(217, 119, 6, 0.6)",
                overviewRulerLane: vscode.OverviewRulerLane.Right,
                gutterIconPath: this._createGutterIcon("medium"),
                gutterIconSize: "contain",
                after: {
                    color: "rgba(217, 119, 6, 0.5)",
                    fontStyle: "italic",
                },
            }),
            low: vscode.window.createTextEditorDecorationType({
                isWholeLine: true,
                backgroundColor: "rgba(101, 163, 13, 0.08)",
                borderWidth: "0 0 1px 0",
                borderColor: "rgba(101, 163, 13, 0.5)",
                borderStyle: "dotted",
                overviewRulerColor: "rgba(101, 163, 13, 0.5)",
                overviewRulerLane: vscode.OverviewRulerLane.Right,
                gutterIconPath: this._createGutterIcon("low"),
                gutterIconSize: "contain",
            }),
            info: vscode.window.createTextEditorDecorationType({
                isWholeLine: false,
                borderWidth: "0 0 1px 0",
                borderColor: "rgba(37, 99, 235, 0.4)",
                borderStyle: "dotted",
                overviewRulerColor: "rgba(37, 99, 235, 0.4)",
                overviewRulerLane: vscode.OverviewRulerLane.Right,
            }),
        };
    }

    /**
     * Set decorations on an editor based on diagnostics.
     * @param {vscode.TextEditor} editor
     * @param {vscode.Diagnostic[]} diagnostics
     */
    setDecorations(editor, diagnostics) {
        // Clear existing decorations
        this.clearDecorations(editor);

        // Group diagnostics by severity
        const grouped = {
            critical: [],
            high: [],
            medium: [],
            low: [],
            info: [],
        };

        for (const diagnostic of diagnostics) {
            const severity = this._mapSeverity(diagnostic.severity);
            const decoration = {
                range: diagnostic.range,
                hoverMessage: this._createHoverMessage(diagnostic),
            };

            // Add inline message for high severity
            if (severity === "critical" || severity === "high") {
                decoration.renderOptions = {
                    after: {
                        contentText: ` ⚠ ${diagnostic.message.substring(0, 60)}`,
                    },
                };
            }

            grouped[severity].push(decoration);
        }

        // Apply decorations by severity
        for (const [severity, decorations] of Object.entries(grouped)) {
            if (decorations.length > 0) {
                editor.setDecorations(
                    this.decorationTypes[severity],
                    decorations
                );
            }
        }
    }

    /**
     * Update decorations for the current editor.
     * @param {vscode.TextEditor} editor
     */
    updateDecorations(editor) {
        if (!editor) return;

        const diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
        const codeshieldDiagnostics = diagnostics.filter(
            (d) => d.source === "codeshield-ai"
        );

        this.setDecorations(editor, codeshieldDiagnostics);
    }

    /**
     * Clear all decorations from an editor.
     * @param {vscode.TextEditor} editor
     */
    clearDecorations(editor) {
        if (!editor) return;

        for (const decorationType of Object.values(this.decorationTypes)) {
            editor.setDecorations(decorationType, []);
        }
    }

    /**
     * Map VS Code diagnostic severity to our severity levels.
     * @param {vscode.DiagnosticSeverity} severity
     * @returns {string}
     */
    _mapSeverity(severity) {
        switch (severity) {
            case vscode.DiagnosticSeverity.Error:
                return "critical";
            case vscode.DiagnosticSeverity.Warning:
                return "medium";
            case vscode.DiagnosticSeverity.Information:
                return "low";
            case vscode.DiagnosticSeverity.Hint:
                return "info";
            default:
                return "low";
        }
    }

    /**
     * Create a hover message for a diagnostic.
     * @param {vscode.Diagnostic} diagnostic
     * @returns {vscode.MarkdownString}
     */
    _createHoverMessage(diagnostic) {
        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.supportHtml = true;

        const severity = this._mapSeverity(diagnostic.severity);
        const emoji = {
            critical: "🔴",
            high: "🟠",
            medium: "🟡",
            low: "🟢",
            info: "🔵",
        }[severity];

        md.appendMarkdown(`### ${emoji} ${diagnostic.message}\n\n`);

        if (diagnostic.code) {
            md.appendMarkdown(`**Code:** ${diagnostic.code}\n\n`);
        }

        md.appendMarkdown(
            `[Apply Fix](command:codeshield.applyFix) | [Show Details](command:codeshield.showDetails)\n\n`
        );
        md.appendMarkdown(`*Detected by CodeShield AI*\n`);

        return md;
    }

    /**
     * Create a gutter icon URI for a severity level.
     * @param {string} severity
     * @returns {vscode.Uri}
     */
    _createGutterIcon(severity) {
        // Use theme icons instead of custom SVGs
        const iconMap = {
            critical: "$(error)",
            high: "$(warning)",
            medium: "$(info)",
            low: "$(pass)",
        };

        // Return null - we'll use the theme icon approach in the decoration type
        return undefined;
    }

    /**
     * Dispose all decoration types.
     */
    dispose() {
        for (const decorationType of Object.values(this.decorationTypes)) {
            decorationType.dispose();
        }
    }
}

module.exports = {
    VulnerabilityDecorations,
};
