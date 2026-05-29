"""
Jenkins Plugin / Pipeline Generator for CodeShield AI.

Generates Jenkinsfile snippets and pipeline stages with:
- Blue Ocean visualization support
- Quality gate integration (fail pipeline on critical/high)
- Color-coded console output for severity levels
- Artifact archiving (SARIF, HTML reports)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

ANSI_RED = "\\u001B[31m"
ANSI_GREEN = "\\u001B[32m"
ANSI_YELLOW = "\\u001B[33m"
ANSI_CYAN = "\\u001B[36m"
ANSI_BOLD = "\\u001B[1m"
ANSI_RESET = "\\u001B[0m"


@dataclass
class JenkinsConfig:
    """Configuration for Jenkins pipeline generation."""

    stage_name: str = "Security Scan"
    agent_label: str = ""
    agent_docker_image: str = "python:3.11-slim"
    use_docker_agent: bool = True
    scan_type: str = "full"
    languages: List[str] = field(default_factory=lambda: ["python", "javascript"])
    severity_threshold: str = "MEDIUM"
    fail_on: str = "HIGH"
    output_formats: List[str] = field(default_factory=lambda: ["sarif", "html"])
    api_url: str = "https://api.codeshield.ai"
    timeout_minutes: int = 10
    archive_artifacts: bool = True
    publish_html: bool = True
    quality_gate: bool = True
    credentials_id: str = "codeshield-api-token"
    fail_pipeline: bool = True

    @property
    def timeout_seconds(self) -> int:
        return self.timeout_minutes * 60


class JenkinsPluginGenerator:
    """Generator for Jenkins pipeline integration."""

    def __init__(self, api_base_url: str = "https://api.codeshield.ai") -> None:
        self.api_base_url = api_base_url.rstrip("/")
        self.default_config = JenkinsConfig()

    def generate_declarative_pipeline(self, config: Optional[JenkinsConfig] = None) -> str:
        if config is None:
            config = self.default_config
        agent_block = self._generate_agent_block(config)
        env_block = self._generate_environment_block(config)
        scan_stage = self._generate_scan_stage(config)
        gate_stage = self._generate_quality_gate_stage(config)
        post_block = self._generate_post_always(config)

        lines = [
            "// CodeShield AI - Jenkins Declarative Pipeline",
            "pipeline {",
            "    agent " + agent_block,
            "    options {",
            "        timeout(time: " + str(config.timeout_minutes + 5) + ", unit: 'MINUTES')",
            "        buildDiscarder(logRotator(numToKeepStr: '50'))",
            "        timestamps()",
            "        ansiColor('xterm')",
            "    }",
            env_block,
            "    stages {",
            self._generate_checkout_stage(),
            scan_stage,
        ]
        if config.quality_gate:
            lines.append(gate_stage)
        lines.extend([
            "    }",
            "    post {",
            "        always {",
            post_block,
            "        }",
            "        success {",
            "            echo \"\\u001B[32m[CodeShield] GREEN: security scan passed the quality gate\\u001B[0m\"",
            "        }",
            "        failure {",
            "            echo \"\\u001B[31m[CodeShield] RED: security scan failed the quality gate\\u001B[0m\"",
            "        }",
            "    }",
            "}",
        ])
        return "\n".join(lines)

    def generate_scripted_pipeline(self, config: Optional[JenkinsConfig] = None) -> str:
        if config is None:
            config = self.default_config
        node_label = "'" + config.agent_label + "'" if config.agent_label else ""
        timeout_val = config.timeout_minutes + 5
        checkout = self._generate_scripted_checkout()
        scan = self._generate_scripted_scan(config)
        gate = self._generate_scripted_quality_gate(config) if config.quality_gate else ""
        post = self._generate_scripted_post(config)
        lines = [
            "// CodeShield AI - Jenkins Scripted Pipeline",
            "node(" + node_label + ") {",
            "    timeout(time: " + str(timeout_val) + ", unit: 'MINUTES') {",
            "        timestamps {",
            "            ansiColor('xterm') {",
            "                try {",
            checkout,
            scan,
            gate,
            "                } catch (Exception e) {",
            "                    currentBuild.result = 'FAILURE'",
            "                    throw e",
            "                } finally {",
            post,
            "                }",
            "            }",
            "        }",
            "    }",
            "}",
        ]
        return "\n".join(lines)

    def generate_shared_library_step(self, config: Optional[JenkinsConfig] = None) -> str:
        if config is None:
            config = self.default_config
        api = self.api_base_url
        creds = config.credentials_id
        timeout_s = config.timeout_minutes * 60
        retry_count = config.timeout_minutes * 12

        lines = [
            "// vars/codeshieldScan.groovy",
            "def call(Map args = [:]) {",
            "    def config = [",
            "        scanType: args.scanType ?: 'full',",
            "        languages: args.languages ?: 'python,javascript',",
            "        severityThreshold: args.severityThreshold ?: 'MEDIUM',",
            "        failOn: args.failOn ?: 'HIGH',",
            "        outputFormat: args.outputFormat ?: 'sarif',",
            "        timeout: args.timeout ?: 10,",
            "        apiUrl: args.apiUrl ?: '%s'," % api,
            "        credentialsId: args.credentialsId ?: '%s'," % creds,
            "        archiveArtifacts: args.archiveArtifacts != null ? args.archiveArtifacts : true,",
            "        qualityGate: args.qualityGate != null ? args.qualityGate : true,",
            "    ]",
            "    def RED = '%s'" % ANSI_RED,
            "    def GREEN = '%s'" % ANSI_GREEN,
            "    def CYAN = '%s'" % ANSI_CYAN,
            "    def BOLD = '%s'" % ANSI_BOLD,
            "    def RESET = '%s'" % ANSI_RESET,
            "    stage('CodeShield Security Scan') {",
            "        withCredentials([string(credentialsId: config.credentialsId, variable: 'CODESHIELD_API_TOKEN')]) {",
            "            echo \"${CYAN}=== CodeShield AI Security Scan ===${RESET}\"",
            "            sh 'pip install codeshield-cli 2>/dev/null || true'",
            "            def configJson = '{\"scan_type\":\"' + config.scanType + '\",\"languages\":[' + config.languages.split(',').collect{'\"'+it.trim()+'\"'}.join(',') + '],\"severity_threshold\":\"' + config.severityThreshold + '\",\"output_format\":\"sarif\",\"timeout\":' + (config.timeout * 60) + '}'",
            "            writeFile file: 'codeshield-config.json', text: configJson",
            "            sh 'zip -r source-code.zip . -x \"*.git/*\" -x \"node_modules/*\" -x \".venv/*\" -x \"target/*\" -x \"build/*\" -x \"*.pyc\" -x \"__pycache__/*\" 2>/dev/null || true'",
            "            def scanResponse = sh(script: 'curl -s -X POST \"' + config.apiUrl + '/api/scan/zip\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" -F \"file=@source-code.zip\" -F \"config=@codeshield-config.json\"', returnStdout: true).trim()",
            "            def scanJson = readJSON text: scanResponse",
            "            env.SCAN_ID = scanJson.scan_id",
            "            echo \"${CYAN}Scan started: ${env.SCAN_ID}${RESET}\"",
            "            def status = 'running'",
            "            def elapsed = 0",
            "            while (status == 'running' || status == 'pending') {",
            "                sleep 5; elapsed += 5",
            "                def sr = sh(script: 'curl -s \"' + config.apiUrl + '/api/scan/' + env.SCAN_ID + '/status\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\"', returnStdout: true).trim()",
            "                def sj = readJSON text: sr",
            "                status = sj.status",
            "                echo \"${CYAN}Status: ${status}${RESET}\"",
            "                if (elapsed > %d) { error(\"${RED}Timed out${RESET}\") }" % timeout_s,
            "            }",
            "            if (status == 'failed') { error(\"${RED}Security scan failed${RESET}\") }",
            "            sh 'curl -s \"' + config.apiUrl + '/api/scan/' + env.SCAN_ID + '/results\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" > codeshield-results.json'",
            "            sh 'curl -s \"' + config.apiUrl + '/api/export/' + env.SCAN_ID + '?format=sarif\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" > codeshield-results.sarif'",
            "            def results = readJSON file: 'codeshield-results.json'",
            "            def criticalCount = results.stats?.critical ?: 0",
            "            def highCount = results.stats?.high ?: 0",
            "            def mediumCount = results.stats?.medium ?: 0",
            "            def lowCount = results.stats?.low ?: 0",
            "            echo \"${BOLD}===== CodeShield AI Scan Results =====${RESET}\"",
            "            echo \"${RED}Critical: ${criticalCount} High: ${highCount} Medium: ${mediumCount} Low: ${lowCount}${RESET}\"",
            "            if (config.archiveArtifacts) { archiveArtifacts artifacts: 'codeshield-results.*', allowEmptyArchive: true }",
            "            if (config.qualityGate) {",
            "                def gatePassed = true",
            "                switch (config.failOn) { case 'CRITICAL': if (criticalCount > 0) gatePassed = false; break; case 'HIGH': if (criticalCount > 0 || highCount > 0) gatePassed = false; break; case 'MEDIUM': if (criticalCount > 0 || highCount > 0 || mediumCount > 0) gatePassed = false; break }",
            "                if (!gatePassed) { currentBuild.result = 'FAILURE'; error(\"${RED}Security gate FAILED${RESET}\") } else { echo \"${GREEN}Security gate PASSED${RESET}\" }",
            "            }",
            "        }",
            "    }",
            "}",
        ]
        return "\n".join(lines)

    def generate_stage_snippet(self, config: Optional[JenkinsConfig] = None) -> str:
        if config is None:
            config = self.default_config
        retry_count = str(config.timeout_minutes * 12)
        lines = [
            "        // CodeShield AI Security Scan Stage",
            "        stage('%s') {" % config.stage_name,
            "            steps {",
            "                withCredentials([string(credentialsId: '%s', variable: 'CODESHIELD_API_TOKEN')]) {" % config.credentials_id,
            "                    sh '''",
            "                        echo '=== CodeShield AI Security Scan ==='",
            "                        pip install codeshield-cli 2>/dev/null || true",
            "                        zip -r source-code.zip . -x '*.git/*' -x 'node_modules/*' -x '.venv/*' 2>/dev/null",
            "                        SCAN_RESPONSE=$(curl -s -X POST \"%s/api/scan/zip\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" -F 'file=@source-code.zip')" % self.api_base_url,
            "                        SCAN_ID=$(echo '$SCAN_RESPONSE' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"scan_id\"])')",
            "                        for i in $(seq 1 %s); do" % retry_count,
            "                            STATUS=$(curl -s \"%s/api/scan/$SCAN_ID/status\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"status\"])')" % self.api_base_url,
            "                            [ '$STATUS' = 'completed' ] && break",
            "                            [ '$STATUS' = 'failed' ] && exit 1",
            "                            sleep 5",
            "                        done",
            "                        curl -s \"%s/api/export/$SCAN_ID?format=sarif\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" > codeshield-results.sarif" % self.api_base_url,
            "                    '''",
            "                }",
            "            }",
            "            post {",
            "                always { archiveArtifacts artifacts: 'codeshield-results.sarif', allowEmptyArchive: true }",
            "            }",
            "        }",
        ]
        return "\n".join(lines)

    def _generate_agent_block(self, config: JenkinsConfig) -> str:
        if config.use_docker_agent:
            return "{ docker { image '%s' } }" % config.agent_docker_image
        return "any"

    def _generate_environment_block(self, config: JenkinsConfig) -> str:
        return "    environment {\n        CODESHIELD_API_URL = '%s'\n        CODESHIELD_SCAN_TYPE = '%s'\n        CODESHIELD_LANGUAGES = '%s'\n        CODESHIELD_SEVERITY_THRESHOLD = '%s'\n        CODESHIELD_FAIL_ON = '%s'\n        CODESHIELD_TIMEOUT = '%s'\n    }" % (
            self.api_base_url, config.scan_type, ",".join(config.languages),
            config.severity_threshold, config.fail_on, str(config.timeout_seconds),
        )

    def _generate_checkout_stage(self) -> str:
        return "        stage('Checkout') {\n            steps {\n                checkout scm\n                script { env.GIT_COMMIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim() }\n            }\n        }"

    def _generate_scan_stage(self, config: JenkinsConfig) -> str:
        return "        stage('%s') {\n            steps {\n                withCredentials([string(credentialsId: '%s', variable: 'CODESHIELD_API_TOKEN')]) {\n                    script {\n                        writeFile file: 'codeshield-config.json', text: '{\"scan_type\":\"' + \"$CODESHIELD_SCAN_TYPE\" + '\",\"languages\":[' + \"$CODESHIELD_LANGUAGES\".split(',').collect{'\"'+it+'\"'}.join(',') + '],\"severity_threshold\":\"' + \"$CODESHIELD_SEVERITY_THRESHOLD\" + '\",\"output_format\":\"sarif\",\"timeout\":' + \"$CODESHIELD_TIMEOUT\" + '}'\n                        sh 'zip -r source-code.zip . -x \"*.git/*\" -x \"node_modules/*\" -x \".venv/*\" 2>/dev/null || true'\n                        def scanResponse = sh(script: 'curl -s -X POST \"' + \"$CODESHIELD_API_URL\" + '/api/scan/zip\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" -F \"file=@source-code.zip\" -F \"config=@codeshield-config.json\"', returnStdout: true).trim()\n                        def scanJson = readJSON text: scanResponse\n                        env.SCAN_ID = scanJson.scan_id\n                        def status = 'running'; def elapsed = 0\n                        while (status == 'running' || status == 'pending') { sleep 5; elapsed += 5; def sr = sh(script: 'curl -s \"' + \"$CODESHIELD_API_URL\" + '/api/scan/' + env.SCAN_ID + '/status\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\"', returnStdout: true).trim(); def sj = readJSON text: sr; status = sj.status; if (elapsed > %s) { error('Timed out') } }\n                        if (status == 'failed') { error('Scan failed') }\n                        sh 'curl -s \"' + \"$CODESHIELD_API_URL\" + '/api/scan/' + env.SCAN_ID + '/results\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" > codeshield-results.json'\n                        sh 'curl -s \"' + \"$CODESHIELD_API_URL\" + '/api/export/' + env.SCAN_ID + '?format=sarif\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" > codeshield-results.sarif'\n                        sh 'curl -s \"' + \"$CODESHIELD_API_URL\" + '/api/export/' + env.SCAN_ID + '?format=html\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" > codeshield-report.html'\n                        def results = readJSON file: 'codeshield-results.json'\n                        def critical = results.stats?.critical ?: 0\n                        def high = results.stats?.high ?: 0\n                        def riskScore = results.risk_score ?: 0\n                        currentBuild.description = 'CodeShield: C=' + critical + ' H=' + high + ' Risk=' + riskScore\n                    }\n                }\n            }\n        }" % (config.stage_name, config.credentials_id, str(config.timeout_seconds))

    def _generate_quality_gate_stage(self, config: JenkinsConfig) -> str:
        return "        stage('Security Quality Gate') {\n            steps {\n                script {\n                    def results = readJSON file: 'codeshield-results.json'\n                    def critical = results.stats?.critical ?: 0\n                    def high = results.stats?.high ?: 0\n                    def medium = results.stats?.medium ?: 0\n                    def gatePassed = true\n                    switch (\"$CODESHIELD_FAIL_ON\") { case 'CRITICAL': if (critical > 0) gatePassed = false; break; case 'HIGH': if (critical > 0 || high > 0) gatePassed = false; break; case 'MEDIUM': if (critical > 0 || high > 0 || medium > 0) gatePassed = false; break }\n                    if (!gatePassed) { error(\"Security gate failed: vulnerabilities found at or above '$CODESHIELD_FAIL_ON'\") }\n                }\n            }\n        }"

    def _generate_post_always(self, config: JenkinsConfig) -> str:
        lines = []
        if config.archive_artifacts:
            lines.append("            archiveArtifacts artifacts: 'codeshield-results.*,codeshield-report.*', allowEmptyArchive: true")
        if config.publish_html:
            lines.append("            publishHTML([allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true, reportDir: '.', reportFiles: 'codeshield-report.html', reportName: 'CodeShield AI Security Report'])")
        return "\n".join(lines)

    def _generate_scripted_checkout(self) -> str:
        return "                    stage('Checkout') {\n                        checkout scm\n                        env.GIT_COMMIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()\n                    }"

    def _generate_scripted_scan(self, config: JenkinsConfig) -> str:
        return "                    stage('Security Scan') {\n                        withCredentials([string(credentialsId: '%s', variable: 'CODESHIELD_API_TOKEN')]) {\n                            sh 'echo \"=== CodeShield AI Security Scan ===\"'\n                            sh 'pip install codeshield-cli 2>/dev/null || true'\n                            sh 'zip -r source-code.zip . -x \"*.git/*\" -x \"node_modules/*\" -x \".venv/*\" 2>/dev/null'\n                            sh 'curl -s -X POST \"%s/api/scan/zip\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" -F \"file=@source-code.zip\" > scan-response.json'\n                            sh 'for i in $(seq 1 %s); do SCAN_ID=$(cat scan-response.json | python3 -c \"import sys,json; print(json.load(sys.stdin)[\\'scan_id\\'])\"); STATUS=$(curl -s \"%s/api/scan/$SCAN_ID/status\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" | python3 -c \"import sys,json; print(json.load(sys.stdin)[\\'status\\'])\"); [ \"$STATUS\" = \"completed\" ] && break; [ \"$STATUS\" = \"failed\" ] && exit 1; sleep 5; done'\n                            sh 'SCAN_ID=$(cat scan-response.json | python3 -c \"import sys,json; print(json.load(sys.stdin)[\\'scan_id\\'])\"); curl -s \"%s/api/export/$SCAN_ID?format=sarif\" -H \"Authorization: Bearer $CODESHIELD_API_TOKEN\" > codeshield-results.sarif'\n                        }\n                    }" % (config.credentials_id, self.api_base_url, str(config.timeout_minutes * 12), self.api_base_url, self.api_base_url)

    def _generate_scripted_quality_gate(self, config: JenkinsConfig) -> str:
        return "                    stage('Quality Gate') {\n                        def results = readJSON file: 'codeshield-results.json'\n                        def critical = results.stats?.critical ?: 0\n                        def high = results.stats?.high ?: 0\n                        if (critical > 0 || high > 0) {\n                            currentBuild.result = 'FAILURE'\n                            error(\"Security gate failed: Critical or High vulnerabilities found\")\n                        }\n                    }"

    def _generate_scripted_post(self, config: JenkinsConfig) -> str:
        lines = ["                        // Archive and cleanup"]
        if config.archive_artifacts:
            lines.append("                        archiveArtifacts artifacts: 'codeshield-results.*,codeshield-report.*', allowEmptyArchive: true")
        return "\n".join(lines)

    def generate_all(self, output_dir: str, config: Optional[JenkinsConfig] = None) -> Dict[str, str]:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        if config is None:
            config = JenkinsConfig()
        files = {}
        (out_path / "Jenkinsfile-declarative").write_text(self.generate_declarative_pipeline(config))
        files["declarative"] = str(out_path / "Jenkinsfile-declarative")
        (out_path / "Jenkinsfile-scripted").write_text(self.generate_scripted_pipeline(config))
        files["scripted"] = str(out_path / "Jenkinsfile-scripted")
        vars_dir = out_path / "vars"
        vars_dir.mkdir(exist_ok=True)
        (vars_dir / "codeshieldScan.groovy").write_text(self.generate_shared_library_step(config))
        files["shared_library"] = str(vars_dir / "codeshieldScan.groovy")
        readme = self._generate_readme()
        (out_path / "README.md").write_text(readme)
        files["readme"] = str(out_path / "README.md")
        logger.info("Generated Jenkins files in %s", output_dir)
        return files

    def _generate_readme(self) -> str:
        return "# CodeShield AI - Jenkins Integration\n\n## Setup\n\n### 1. Configure API Token Credential\n\nIn Jenkins, go to **Manage Jenkins > Manage Credentials** and add a new \"Secret text\" credential with your CodeShield AI API token. Set the ID to `codeshield-api-token`.\n\n### 2. Use Declarative Pipeline\n\n```groovy\n// Jenkinsfile\npipeline {\n    agent any\n    stages {\n        stage('Build') {\n            steps {\n                sh 'make build'\n            }\n        }\n        stage('Security Scan') {\n            steps {\n                codeshieldScan(\n                    scanType: 'full',\n                    languages: 'python,javascript',\n                    failOn: 'HIGH'\n                )\n            }\n        }\n    }\n}\n```\n\n### 3. Use Shared Library\n\nIn **Manage Jenkins > Configure System > Global Pipeline Libraries**, add:\n- Name: `codeshield`\n- Default version: `main`\n- Retrieval method: Modern SCM\n\nThen in your pipeline:\n```groovy\n@Library('codeshield') _\n\ncodeshieldScan(failOn: 'HIGH')\n```\n\n## Blue Ocean Support\n\nAll stages are automatically compatible with Jenkins Blue Ocean.\nThe quality gate stage will show red/green status for security results.\n\n## Console Output\n\nThe scan produces color-coded console output:\n- Critical findings in red\n- High findings in orange\n- Medium findings in yellow\n- Low findings in green\n"
