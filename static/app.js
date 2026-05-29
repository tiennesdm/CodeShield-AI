// Global State
let severityChartInstance = null;
let categoryChartInstance = null;
let monacoEditorInstance = null;
let currentEditingFilePath = null;

let currentState = {
  view: 'welcome', // 'welcome', 'scanning', 'results'
  health: 'offline',
  activeScanId: null,
  activeScanData: null,
  vulnerabilities: [],
  activeFilters: {
    search: '',
    severity: 'ALL'
  }
};

// DOM Elements
const docElements = {
  statusDot: document.getElementById('status-dot'),
  statusText: document.getElementById('status-text'),
  welcomeView: document.getElementById('welcome-view'),
  scanningView: document.getElementById('scanning-view'),
  resultsView: document.getElementById('results-view'),
  dropZone: document.getElementById('drop-zone'),
  zipInput: document.getElementById('zip-file-input'),
  selectedFileText: document.getElementById('selected-file-info'),
  historyList: document.getElementById('scan-history-list'),
  sidebar: document.getElementById('sidebar'),
  toggleSidebarBtn: document.getElementById('toggle-sidebar-btn'),
  
  // Scanning progress
  scanningProjectName: document.getElementById('scanning-project-name'),
  scanningScanId: document.getElementById('scanning-scan-id'),
  progressPhase: document.getElementById('progress-phase'),
  progressPercent: document.getElementById('progress-percent'),
  progressBarFill: document.getElementById('progress-bar-fill'),
  consoleLog: document.getElementById('console-log'),
  
  // Results view
  resultsProjectName: document.getElementById('results-project-name'),
  resultsScanId: document.getElementById('results-scan-id'),
  resultsLanguages: document.getElementById('results-languages'),
  resultsTotalFiles: document.getElementById('results-total-files'),
  resultsDuration: document.getElementById('results-duration'),
  resultsRiskScore: document.getElementById('results-risk-score'),
  downloadPdfBtn: document.getElementById('download-pdf-btn'),
  downloadZipBtn: document.getElementById('download-zip-btn'),
  
  // Severity counts
  countCritical: document.getElementById('count-critical'),
  countHigh: document.getElementById('count-high'),
  countMedium: document.getElementById('count-medium'),
  countLow: document.getElementById('count-low'),
  countInfo: document.getElementById('count-info'),
  
  // Findings
  findingsTotalCount: document.getElementById('findings-total-count'),
  findingSearch: document.getElementById('finding-search'),
  severityFilter: document.getElementById('severity-filter'),
  findingsList: document.getElementById('findings-list'),
  statsMiniSummary: document.getElementById('stats-mini-summary')
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  feather.replace();
  checkHealth();
  loadHistory();
  setupDragAndDrop();
  
  // Keep health check running every 30 seconds
  setInterval(checkHealth, 30000);
  
  // Sidebar toggle
  docElements.toggleSidebarBtn.addEventListener('click', () => {
    docElements.sidebar.classList.toggle('collapsed');
  });

  // Theme Toggle Logic
  const themeToggleBtn = document.getElementById('theme-toggle-btn');
  const currentTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', currentTheme);
  updateThemeIcon(currentTheme);

  themeToggleBtn.addEventListener('click', () => {
    const activeTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', activeTheme);
    localStorage.setItem('theme', activeTheme);
    updateThemeIcon(activeTheme);
  });

  function updateThemeIcon(theme) {
    const icon = themeToggleBtn.querySelector('i');
    if (theme === 'dark') {
      icon.setAttribute('data-feather', 'sun');
    } else {
      icon.setAttribute('data-feather', 'moon');
    }
    if (window.feather) feather.replace();
  }

  // Code Editor Overlay Listeners
  const closeBtn = document.getElementById('editor-close-btn');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      document.getElementById('editor-overlay').classList.add('hidden');
      if (monacoEditorInstance) {
        monacoEditorInstance.dispose();
        monacoEditorInstance = null;
      }
    });
  }
  
  const saveBtn = document.getElementById('editor-save-btn');
  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      if (!monacoEditorInstance || !currentEditingFilePath) return;
      
      const content = monacoEditorInstance.getValue();
      const scanId = currentState.activeScanId;
      
      try {
        const response = await fetch(`/api/scan/${scanId}/file`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            file_path: currentEditingFilePath,
            content: content
          })
        });
        
        if (response.ok) {
          alert("File saved successfully!");
          document.getElementById('editor-overlay').classList.add('hidden');
          monacoEditorInstance.dispose();
          monacoEditorInstance = null;
          // Optionally trigger re-load results
          loadScanResults(scanId);
        } else {
          const err = await response.json();
          alert("Failed to save: " + (err.detail || "Unknown error"));
        }
      } catch (err) {
        alert("Save failed: " + err.message);
      }
    });
  }
});

// Switch Tabs between ZIP and Github
function switchTab(type) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  
  if (type === 'zip') {
    document.getElementById('tab-zip').classList.add('active');
    document.getElementById('zip-form').classList.add('active');
  } else {
    document.getElementById('tab-github').classList.add('active');
    document.getElementById('github-form').classList.add('active');
  }
}

// Collapsible Advanced Settings
function toggleAdvancedSettings(type) {
  const settingsDiv = document.getElementById(`advanced-settings-${type}`);
  const trigger = settingsDiv.previousElementSibling;
  
  settingsDiv.classList.toggle('hidden');
  trigger.classList.toggle('active');
  
  const icon = document.getElementById(`adv-chevron-${type}`);
  if (settingsDiv.classList.contains('hidden')) {
    icon.setAttribute('data-feather', 'chevron-down');
  } else {
    icon.setAttribute('data-feather', 'chevron-up');
  }
  feather.replace();
}

// Drag & Drop Configuration
function setupDragAndDrop() {
  const dropZone = docElements.dropZone;
  const fileInput = docElements.zipInput;
  
  dropZone.addEventListener('click', () => fileInput.click());
  
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  });
  
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    }, false);
  });
  
  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    }, false);
  });
  
  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0 && files[0].name.endsWith('.zip')) {
      fileInput.files = files;
      handleFileSelected(files[0]);
    } else {
      showLog('Only ZIP files are supported!', 'error');
    }
  }, false);
}

function handleFileSelected(file) {
  docElements.selectedFileText.textContent = `Selected: ${file.name} (${(file.size / (1024 * 1024)).toFixed(2)} MB)`;
}

// Health check API call
async function checkHealth() {
  try {
    const response = await fetch('/api/health');
    if (response.ok) {
      updateHealthStatus('online', 'Server Online');
    } else {
      updateHealthStatus('offline', 'Server Error');
    }
  } catch (error) {
    updateHealthStatus('offline', 'Server Offline');
  }
}

function updateHealthStatus(status, text) {
  currentState.health = status;
  docElements.statusText.textContent = text;
  docElements.statusDot.className = `pulse-dot ${status}`;
}

// Load Past Scans History
async function loadHistory() {
  try {
    const response = await fetch('/api/history?limit=15');
    if (response.ok) {
      const data = await response.json();
      renderHistoryList(data.scans || []);
    }
  } catch (error) {
    console.error('Failed to load scan history:', error);
  }
}

function renderHistoryList(scans) {
  if (scans.length === 0) {
    docElements.historyList.innerHTML = '<div class="empty-history">No past scans found</div>';
    return;
  }
  
  let html = '';
  scans.forEach(scan => {
    const timeStr = scan.start_time ? new Date(scan.start_time).toLocaleDateString() : 'Unknown';
    const totalIssues = scan.vulnerability_count !== undefined ? scan.vulnerability_count : (scan.stats ? Object.values(scan.stats).reduce((a,b) => a+b, 0) : 0);
    const activeClass = currentState.activeScanId === scan.scan_id ? 'active' : '';
    
    html += `
      <div class="history-item ${activeClass}" onclick="loadScanResults('${scan.scan_id}')">
        <div class="history-name" title="${scan.name}">${scan.name}</div>
        <div class="history-meta">
          <span>${timeStr}</span>
          <span class="history-status">
            <span class="status-dot ${scan.status.toLowerCase()}"></span>
            ${totalIssues} issues
          </span>
        </div>
      </div>
    `;
  });
  
  docElements.historyList.innerHTML = html;
}

// Fetch and render single Scan Results
async function loadScanResults(scanId) {
  try {
    showView('loading');
    const response = await fetch(`/api/scan/${scanId}/results`);
    if (response.ok) {
      const results = await response.json();
      currentState.activeScanId = scanId;
      currentState.activeScanData = results;
      currentState.vulnerabilities = results.vulnerabilities || [];
      
      // Update history sidebar active state highlights
      document.querySelectorAll('.history-item').forEach(el => el.classList.remove('active'));
      loadHistory(); // refresh to load new listings
      
      renderResultsPage(results);
      showView('results');
    } else {
      alert('Failed to load scan results. The scan might still be running.');
      showView('welcome');
    }
  } catch (error) {
    console.error('Error fetching scan results:', error);
    alert('Failed to connect to the backend server.');
    showView('welcome');
  }
}

// Display specific Single-Page App View
function showView(view) {
  currentState.view = view;
  
  docElements.welcomeView.classList.add('hidden');
  docElements.scanningView.classList.add('hidden');
  docElements.resultsView.classList.add('hidden');
  
  if (view === 'welcome') {
    docElements.welcomeView.classList.remove('hidden');
  } else if (view === 'scanning') {
    docElements.scanningView.classList.remove('hidden');
  } else if (view === 'results') {
    docElements.resultsView.classList.remove('hidden');
  }
}

function showDashboard() {
  currentState.activeScanId = null;
  currentState.activeScanData = null;
  showView('welcome');
  loadHistory();
}

// Clear and add Console logs
function clearLogs() {
  docElements.consoleLog.innerHTML = '';
}

function showLog(message, type = 'info') {
  const timestamp = new Date().toLocaleTimeString();
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  entry.innerHTML = `<span>[${timestamp}]</span> ${message}`;
  
  docElements.consoleLog.appendChild(entry);
  docElements.consoleLog.scrollTop = docElements.consoleLog.scrollHeight;
}

// Launch scan for ZIP upload
async function submitZip(event) {
  event.preventDefault();
  if (currentState.health === 'offline') {
    alert('Server is currently offline. Please wait or start the server.');
    return;
  }
  
  const file = docElements.zipInput.files[0];
  if (!file) return;
  
  const name = document.getElementById('zip-scan-name').value;
  const tools = getCheckedValues('tools');
  
  const formData = new FormData();
  formData.append('file', file);
  if (name) formData.append('name', name);
  
  const config = {
    tools: tools,
    severity_filters: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
  };
  formData.append('config', JSON.stringify(config));
  
  try {
    showView('scanning');
    clearLogs();
    showLog('Preparing payload and initiating ZIP file upload...');
    
    docElements.scanningProjectName.textContent = name || file.name.replace('.zip', '');
    
    const response = await fetch('/api/scan/zip', {
      method: 'POST',
      body: formData
    });
    
    if (response.ok) {
      const data = await response.json();
      const scanId = data.scan_id;
      docElements.scanningScanId.textContent = scanId;
      showLog(`Upload successful. Scan initiated with ID: ${scanId}`, 'success');
      startPolling(scanId);
    } else {
      const err = await response.json();
      showLog(`Upload failed: ${err.detail || 'Unknown error'}`, 'error');
      alert(`Scan failed to start: ${err.detail || 'Server error'}`);
      showView('welcome');
    }
  } catch (error) {
    showLog(`Connection error: ${error.message}`, 'error');
    alert('Failed to connect to the backend API.');
    showView('welcome');
  }
}

// Launch scan for GitHub URL
async function submitGithub(event) {
  event.preventDefault();
  if (currentState.health === 'offline') {
    alert('Server is currently offline. Please wait or start the server.');
    return;
  }
  
  const url = document.getElementById('github-url-input').value;
  const name = document.getElementById('github-scan-name').value;
  const tools = getCheckedValues('github_tools');
  
  const payload = {
    source_type: 'github',
    source_url: url,
    name: name || null,
    config: {
      tools: tools,
      severity_filters: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    }
  };
  
  try {
    showView('scanning');
    clearLogs();
    showLog('Connecting to backend to launch GitHub Repository Clone...');
    
    docElements.scanningProjectName.textContent = name || url.split('/').pop();
    
    const response = await fetch('/api/scan/github', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    
    if (response.ok) {
      const data = await response.json();
      const scanId = data.scan_id;
      docElements.scanningScanId.textContent = scanId;
      showLog(`Clone & audit job scheduled. Scan ID: ${scanId}`, 'success');
      startPolling(scanId);
    } else {
      const err = await response.json();
      showLog(`Scan trigger failed: ${err.detail || 'Unknown error'}`, 'error');
      alert(`Scan failed to start: ${err.detail || 'Server error'}`);
      showView('welcome');
    }
  } catch (error) {
    showLog(`Connection error: ${error.message}`, 'error');
    alert('Failed to connect to the backend API.');
    showView('welcome');
  }
}

function getCheckedValues(name) {
  return Array.from(document.querySelectorAll(`input[name="${name}"]:checked`)).map(el => el.value);
}

// Status Polling Loop
let scanWebSocket = null;
let pollingInterval = null;

function startPolling(scanId) {
  if (pollingInterval) clearInterval(pollingInterval);
  if (scanWebSocket) {
    try {
      scanWebSocket.close();
    } catch(e) {}
  }
  
  updateProgress(0, 'Initializing...', 'running');
  
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/api/ws/scan/${scanId}`;
  
  showLog(`Connecting WebSocket for scan ID: ${scanId}...`);
  
  let wsConnected = false;
  try {
    scanWebSocket = new WebSocket(wsUrl);
    
    scanWebSocket.onopen = () => {
      wsConnected = true;
      showLog(`WebSocket connected for scan: ${scanId}`, 'success');
    };
    
    scanWebSocket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'log') {
          showLog(data.message, data.level || 'info');
        } else if (data.type === 'progress') {
          const progress = data.progress || 0;
          const status = data.status || 'running';
          
          let phase = 'Analyzing files...';
          if (progress < 10) phase = 'Cloning / Extracting codebase...';
          else if (progress < 30) phase = 'Detecting programming languages...';
          else if (progress < 80) phase = 'Running security analyzers...';
          else if (progress < 95) {
            if (progress < 82) phase = 'Triage: Deduplicating hash-based findings...';
            else if (progress < 84) phase = 'Triage: Performing semantic similarity checks...';
            else if (progress < 86) phase = 'Triage: Resolving cross-agent alerts...';
            else if (progress < 88) phase = 'Triage: Computing confidence scores...';
            else if (progress < 90) phase = 'Triage: Running AI Triage on HIGH/CRITICAL findings...';
            else phase = 'Triage: Adjusting severity thresholds...';
          }
          else if (progress === 100) phase = 'Completed';
          
          if (status === 'failed') {
            phase = 'Scan Failed';
            showLog(`Error encountered: ${data.error || 'Unknown scanner error'}`, 'error');
          } else {
            showLog(`WebSocket Progress: ${progress}% - ${phase}`);
          }
          
          updateProgress(progress, phase, status);
          
          if (status === 'completed') {
            showLog('Scan completed successfully! Fetching final results...', 'success');
            scanWebSocket.close();
            setTimeout(() => loadScanResults(scanId), 1000);
          } else if (status === 'failed') {
            showLog('Scan failed to complete. Audit aborted.', 'error');
            scanWebSocket.close();
            alert(`Scan failed: ${data.error || 'Unknown database issue'}`);
            setTimeout(() => showView('welcome'), 4000);
          }
        }
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };
    
    scanWebSocket.onerror = (error) => {
      showLog(`WebSocket connection error. Falling back to HTTP polling...`, 'warn');
      startHttpPolling(scanId);
    };
    
    scanWebSocket.onclose = () => {
      if (!wsConnected) {
        startHttpPolling(scanId);
      } else {
        showLog("WebSocket connection closed.");
      }
    };
  } catch (err) {
    showLog(`Failed to construct WebSocket. Falling back to HTTP polling...`, 'warn');
    startHttpPolling(scanId);
  }
}

function startHttpPolling(scanId) {
  if (pollingInterval) clearInterval(pollingInterval);
  showLog("Starting HTTP status polling...");
  pollingInterval = setInterval(async () => {
    try {
      const response = await fetch(`/api/scan/${scanId}/status`);
      if (response.ok) {
        const data = await response.json();
        const progress = data.progress || 0;
        const status = data.status || 'running';
        
        let phase = 'Analyzing files...';
        if (progress < 10) phase = 'Cloning / Extracting codebase...';
        else if (progress < 30) phase = 'Detecting programming languages...';
        else if (progress < 80) phase = 'Running security analyzers...';
        else if (progress < 95) {
          if (progress < 82) phase = 'Triage: Deduplicating hash-based findings...';
          else if (progress < 84) phase = 'Triage: Performing semantic similarity checks...';
          else if (progress < 86) phase = 'Triage: Resolving cross-agent alerts...';
          else if (progress < 88) phase = 'Triage: Computing confidence scores...';
          else if (progress < 90) phase = 'Triage: Running AI Triage on HIGH/CRITICAL findings...';
          else phase = 'Triage: Adjusting severity thresholds...';
        }
        else if (progress === 100) phase = 'Completed';
        
        if (status === 'failed') {
          phase = 'Scan Failed';
          showLog(`Error encountered: ${data.error || 'Unknown scanner error'}`, 'error');
        } else {
          showLog(`HTTP Poll Progress: ${progress}% - ${phase}`);
        }
        
        updateProgress(progress, phase, status);
        
        if (status === 'completed') {
          showLog('Scan completed successfully! Fetching final results...', 'success');
          clearInterval(pollingInterval);
          setTimeout(() => loadScanResults(scanId), 1000);
        } else if (status === 'failed') {
          showLog('Scan failed to complete. Audit aborted.', 'error');
          clearInterval(pollingInterval);
          alert(`Scan failed: ${data.error || 'Unknown database issue'}`);
          setTimeout(() => showView('welcome'), 4000);
        }
      } else {
        showLog('Polling backend... waiting for record to sync', 'warn');
      }
    } catch (error) {
      showLog(`Status fetch exception: ${error.message}`, 'warn');
    }
  }, 2500);
}

const scanAgents = [
  {
    id: 'john',
    name: 'John',
    role: 'SAST Auditor',
    desc: 'Analyzes code for common vulnerabilities and quality issues.',
    icon: 'cpu',
    range: [10, 60],
    activities: {
      pending: 'Awaiting scan initiation...',
      running: 'Scanning files with Bandit, Semgrep, and ESLint...',
      completed: 'Analysis finished. Findings parsed.',
      failed: 'SAST code scan aborted.'
    }
  },
  {
    id: 'sam',
    name: 'Sam',
    role: 'Secret Detector',
    desc: 'Scans files for hardcoded passwords, tokens, and private keys.',
    icon: 'key',
    range: [15, 60],
    activities: {
      pending: 'Awaiting credentials scan window...',
      running: 'Checking for hardcoded API keys, certs, and entropy patterns...',
      completed: 'Secrets detection complete.',
      failed: 'Secrets scan failed.'
    }
  },
  {
    id: 'pam',
    name: 'Pam',
    role: 'SCA Analyst',
    desc: 'Checks packages and dependencies for known CVE vulnerabilities.',
    icon: 'package',
    range: [20, 60],
    activities: {
      pending: 'Awaiting lockfile parsing...',
      running: 'Checking package-lock.json & requirements.txt against CVE databases...',
      completed: 'SCA dependency checks complete.',
      failed: 'Dependency checks failed.'
    }
  },
  {
    id: 'tina',
    name: 'Tina',
    role: 'Taint Analyzer',
    desc: 'Traces data flow to detect injection risks and input issues.',
    icon: 'activity',
    range: [60, 80],
    activities: {
      pending: 'Awaiting dataflow model construction...',
      running: 'Tracing source-to-sink dataflow paths for injections...',
      completed: 'Dataflow taint tracking complete.',
      failed: 'Taint analysis aborted.'
    }
  },
  {
    id: 'triager',
    name: 'Triager',
    role: 'Governance Agent',
    desc: 'Triage findings and deduplicate overlapping alerts.',
    icon: 'shield',
    range: [80, 90],
    activities: {
      pending: 'Awaiting raw findings...',
      running: 'Deduplicating findings and evaluating security policies...',
      completed: 'Triaged and grouped all valid findings.',
      failed: 'Triage checks aborted.'
    }
  },
  {
    id: 'fixer',
    name: 'Fixer',
    role: 'Remediation Engineer',
    desc: 'Generates automated code suggestions and fixes.',
    icon: 'tool',
    range: [90, 95],
    activities: {
      pending: 'Awaiting triage feedback...',
      running: 'Generating code rewrite patches and AST syntax fixes...',
      completed: 'Auto-remediation suggestions compiled.',
      failed: 'Remediation generation failed.'
    }
  },
  {
    id: 'assembler',
    name: 'Report Assembler',
    role: 'Compliance Officer',
    desc: 'Compiles details, calculates risk score, and prepares report.',
    icon: 'file-text',
    range: [95, 100],
    activities: {
      pending: 'Awaiting remediation stats...',
      running: 'Calculating risk levels and generating compliance report...',
      completed: 'Scan report compiled successfully.',
      failed: 'Report assembly aborted.'
    }
  }
];

function renderAgentSwarm(percent, scanStatus) {
  const container = document.getElementById('agent-swarm-grid');
  if (!container) return;
  
  let html = '';
  scanAgents.forEach(agent => {
    let agentStatus = 'pending';
    
    if (scanStatus === 'completed') {
      agentStatus = 'completed';
    } else if (scanStatus === 'failed') {
      if (percent >= agent.range[0] && percent < agent.range[1]) {
        agentStatus = 'failed';
      } else if (percent >= agent.range[1]) {
        agentStatus = 'completed';
      } else {
        agentStatus = 'pending';
      }
    } else {
      if (percent < agent.range[0]) {
        agentStatus = 'pending';
      } else if (percent >= agent.range[0] && percent < agent.range[1]) {
        agentStatus = 'running';
      } else {
        agentStatus = 'completed';
      }
    }
    
    let statusBadgeHtml = '';
    let activityText = '';
    
    if (agentStatus === 'pending') {
      statusBadgeHtml = `<span class="agent-status-badge"><i data-feather="clock"></i> Pending</span>`;
      activityText = agent.activities.pending;
    } else if (agentStatus === 'running') {
      statusBadgeHtml = `<span class="agent-status-badge"><i data-feather="loader" class="agent-spinner"></i> Active</span>`;
      if (agent.id === 'triager') {
        if (percent < 82) {
          activityText = 'Deduplicating hash-based findings...';
        } else if (percent < 84) {
          activityText = 'Performing semantic similarity checks...';
        } else if (percent < 86) {
          activityText = 'Resolving cross-agent alerts...';
        } else if (percent < 88) {
          activityText = 'Computing confidence scores...';
        } else if (percent < 90) {
          activityText = 'Running AI Triage on HIGH/CRITICAL findings...';
        } else {
          activityText = 'Adjusting severity thresholds...';
        }
      } else {
        activityText = agent.activities.running;
      }
    } else if (agentStatus === 'completed') {
      statusBadgeHtml = `<span class="agent-status-badge"><i data-feather="check-circle"></i> Done</span>`;
      activityText = agent.activities.completed;
    } else if (agentStatus === 'failed') {
      statusBadgeHtml = `<span class="agent-status-badge"><i data-feather="alert-circle"></i> Failed</span>`;
      activityText = agent.activities.failed;
    }
    
    html += `
      <div class="agent-card ${agentStatus}">
        <div class="agent-card-left">
          <div class="agent-avatar">
            <i data-feather="${agent.icon}"></i>
          </div>
          <div class="agent-info">
            <span class="agent-name">${agent.name} <span class="agent-role">(${agent.role})</span></span>
            <span class="agent-desc" title="${agent.desc}">${agent.desc}</span>
            <span class="agent-activity-status">${activityText}</span>
          </div>
        </div>
        ${statusBadgeHtml}
      </div>
    `;
  });
  
  container.innerHTML = html;
  feather.replace();
}

function updateConceptHighlights(percent, scanStatus) {
  const ids = ['concept-agentic', 'concept-llm', 'concept-design', 'concept-responsible', 'concept-security'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('highlighted');
  });
  
  if (scanStatus === 'failed') return;
  
  if (scanStatus === 'running' || scanStatus === 'completed') {
    const el = document.getElementById('concept-design');
    if (el) el.classList.add('highlighted');
  }
  
  if ((scanStatus === 'running' && percent >= 10 && percent < 95) || scanStatus === 'completed') {
    const el = document.getElementById('concept-agentic');
    if (el) el.classList.add('highlighted');
  }
  
  if ((scanStatus === 'running' && percent >= 80 && percent < 95) || scanStatus === 'completed') {
    const el = document.getElementById('concept-llm');
    if (el) el.classList.add('highlighted');
  }
  
  if ((scanStatus === 'running' && percent >= 80) || scanStatus === 'completed') {
    const el = document.getElementById('concept-responsible');
    if (el) el.classList.add('highlighted');
  }
  
  if ((scanStatus === 'running' && percent >= 90 && percent < 95) || scanStatus === 'completed') {
    const el = document.getElementById('concept-security');
    if (el) el.classList.add('highlighted');
  }
}

function updateProgress(percent, phaseText, status) {
  docElements.progressPhase.textContent = phaseText;
  docElements.progressPercent.textContent = `${percent}%`;
  docElements.progressBarFill.style.width = `${percent}%`;
  renderAgentSwarm(percent, status);
  updateConceptHighlights(percent, status);
  renderSwarmNetworkGraph(percent, status);
}

// Render Results View
function renderResultsPage(results) {
  // Metadata
  docElements.resultsProjectName.textContent = results.name || `Scan ${results.scan_id}`;
  docElements.resultsScanId.textContent = results.scan_id;
  docElements.resultsLanguages.textContent = results.languages ? results.languages.join(', ') : 'None';
  docElements.resultsTotalFiles.textContent = results.total_files || 0;
  docElements.resultsDuration.textContent = results.scan_duration || 0;
  docElements.resultsRiskScore.textContent = results.risk_score || 0;
  
  // Color the risk score circle based on value
  const score = results.risk_score || 0;
  const color = score > 70 ? 'var(--color-critical)' : score > 40 ? 'var(--color-high)' : score > 15 ? 'var(--color-medium)' : 'var(--color-low)';
  docElements.resultsRiskScore.parentElement.style.borderColor = color;
  docElements.resultsRiskScore.style.color = color;
  
  // Severity Counts
  const stats = results.stats || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  docElements.countCritical.textContent = stats.critical || 0;
  docElements.countHigh.textContent = stats.high || 0;
  docElements.countMedium.textContent = stats.medium || 0;
  docElements.countLow.textContent = stats.low || 0;
  docElements.countInfo.textContent = stats.info || 0;
  
  // PDF Download Action
  docElements.downloadPdfBtn.onclick = () => {
    window.open(`/api/scan/${results.scan_id}/report/pdf`, '_blank');
  };
  
  // ZIP Download Action
  docElements.downloadZipBtn.onclick = () => {
    window.open(`/api/scan/${results.scan_id}/download`, '_blank');
  };
  
  // Render vulnerabilities
  applyFilters();
  
  // Render Analytics Charts
  renderAnalyticsCharts(results);
}

// Filters & Vulnerability Card Renderers
function filterFindings(severity) {
  docElements.severityFilter.value = severity;
  applyFilters();
}

function applyFilters() {
  const searchVal = docElements.findingSearch.value.toLowerCase().trim();
  const severityVal = docElements.severityFilter.value;
  
  currentState.activeFilters.search = searchVal;
  currentState.activeFilters.severity = severityVal;
  
  let filtered = currentState.vulnerabilities;
  
  if (severityVal !== 'ALL') {
    filtered = filtered.filter(v => v.severity.toUpperCase() === severityVal);
  }
  
  if (searchVal) {
    filtered = filtered.filter(v => 
      v.title.toLowerCase().includes(searchVal) || 
      v.category.toLowerCase().includes(searchVal) || 
      v.file_path.toLowerCase().includes(searchVal) ||
      (v.cwe_id && v.cwe_id.toLowerCase().includes(searchVal))
    );
  }
  
  docElements.findingsTotalCount.textContent = filtered.length;
  renderFindingsList(filtered);
}

function renderFindingsList(findings) {
  if (findings.length === 0) {
    docElements.findingsList.innerHTML = `
      <div class="no-findings">
        <i data-feather="check-circle"></i>
        <p>No vulnerabilities found matching current filters.</p>
      </div>
    `;
    feather.replace();
    return;
  }
  
  let html = '';
  findings.forEach(vuln => {
    const severityLower = vuln.severity.toLowerCase();
    const cweText = vuln.cwe_id ? `${vuln.cwe_id} - ${vuln.cwe_name || ''}` : 'CWE-N/A';
    
    // Process code snippet and sanitize for rendering
    let codeHtml = '';
    if (vuln.code_snippet) {
      const lines = vuln.code_snippet.split('\n');
      codeHtml = '<div class="code-block-container">';
      lines.forEach(line => {
        // Highlight matching lines if they have arrow indicator
        const isTainted = line.includes('>>>');
        const cleanLine = escapeHTML(line.replace('>>>', ''));
        codeHtml += `<div class="code-line ${isTainted ? 'tainted' : ''}">${cleanLine}</div>`;
      });
      codeHtml += '</div>';
    }
    
    const flowSteps = [
      { name: 'Input Source', desc: 'Untrusted user input or package dependency entrypoint.', icon: 'arrow-right-circle', color: '#3b82f6' },
      { name: 'Taint Propagation', desc: `Traced line execution at ${vuln.file_path}:${vuln.line_number}`, icon: 'git-commit', color: '#f59e0b' },
      { name: 'Sink / Vulnerable Execution', desc: `${vuln.title} (${vuln.severity} severity)`, icon: 'alert-triangle', color: '#ef4444' }
    ];
    
    let flowHtml = `
      <div class="taint-flow-container" style="margin-top: 16px; margin-bottom: 16px; padding: 16px; background: rgba(0,0,0,0.15); border: 1px solid var(--border-light); border-radius: 8px;">
        <h5 style="font-size: 11px; text-transform: uppercase; color: var(--color-text-dark); font-weight: 700; margin-bottom: 12px; display: flex; align-items: center; gap: 6px; margin-top: 0;">
          <i data-feather="git-pull-request" style="width: 12px; height: 12px;"></i> Visual Exploit / Taint Path
        </h5>
        <div class="flow-steps-wrapper" style="display: flex; align-items: flex-start; justify-content: space-between; position: relative;">
    `;
    
    flowSteps.forEach((step, idx) => {
      flowHtml += `
        <div class="flow-step-item" style="flex: 1; text-align: center; padding: 0 8px; position: relative; z-index: 1;">
          <div class="flow-icon-circle" style="width: 32px; height: 32px; border-radius: 50%; background: ${step.color}20; border: 2px solid ${step.color}; display: inline-flex; align-items: center; justify-content: center; color: ${step.color}; margin-bottom: 8px;">
            <i data-feather="${step.icon}" style="width: 16px; height: 16px;"></i>
          </div>
          <div style="font-weight: 600; font-size: 12px; color: var(--color-text-main); margin-bottom: 4px;">${step.name}</div>
          <div style="font-size: 10px; color: var(--color-text-dark); line-height: 1.4;">${step.desc}</div>
        </div>
      `;
      
      if (idx < flowSteps.length - 1) {
        flowHtml += `
          <div class="flow-step-connector" style="flex: 0.5; height: 2px; background: var(--border-light); margin-top: 15px; position: relative; z-index: 0;"></div>
        `;
      }
    });
    
    flowHtml += `
        </div>
      </div>
    `;

    html += `
      <div class="finding-item ${severityLower}" id="vuln-${vuln.id}">
        <div class="finding-trigger" onclick="toggleFinding('${vuln.id}')">
          <div class="finding-left">
            <span class="sev-badge">${vuln.severity}</span>
            <div class="finding-title-block">
              <span class="finding-title" title="${vuln.title}">${vuln.title}</span>
              <span class="finding-location">${vuln.file_path}:${vuln.line_number}</span>
            </div>
          </div>
          <div class="finding-right">
            <span class="finding-cwe">${cweText}</span>
            <i data-feather="chevron-down" class="finding-chevron"></i>
          </div>
        </div>
        <div class="finding-content">
          <div class="finding-desc-group">
            <h4>Description</h4>
            <p>${escapeHTML(vuln.description)}</p>
          </div>
          ${codeHtml}
          ${flowHtml}
          <div class="finding-desc-group">
            <h4>Suggested Fix</h4>
            <p><strong>Remediation:</strong> ${escapeHTML(vuln.fix_suggestion || 'Review codebase and apply secure patterns.')}</p>
          </div>
          
          <!-- AI Remediation Box -->
          <div class="fix-container" id="fix-container-${vuln.id}">
            <div class="fix-header">
              <h4>AI Security Remediation</h4>
              <span class="fix-status-badge ${vuln.is_fixed ? 'success' : 'ready'}" id="fix-status-${vuln.id}">
                ${vuln.is_fixed ? 'Fixed' : 'Ready'}
              </span>
            </div>
            <div class="fix-actions">
              <button class="action-btn fix-apply-btn" id="fix-btn-${vuln.id}" onclick="applyAutoFix('${vuln.id}', event)" ${vuln.is_fixed ? 'disabled' : ''}>
                <i data-feather="zap"></i> Apply Auto-Fix
              </button>
              <button class="action-btn fix-preview-btn" id="preview-btn-${vuln.id}" onclick="previewAutoFix('${vuln.id}', event)" ${vuln.is_fixed ? 'disabled' : ''}>
                <i data-feather="eye"></i> Preview Diff
              </button>
              <button class="action-btn editor-open-btn" style="background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border-light); color: var(--color-text-main); display: flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 4px; cursor: pointer; transition: all 0.2s;" onclick="openInMonacoEditor('${vuln.id}', event)">
                <i data-feather="edit-2" style="width: 14px; height: 14px;"></i> Open in Editor
              </button>
            </div>
            <div class="fix-preview-area hidden" id="preview-area-${vuln.id}">
              <h5>Proposed Diff:</h5>
              <div class="monaco-diff-container" id="diff-block-${vuln.id}" style="height: 350px; border: 1px solid var(--border-light); border-radius: 4px; overflow: hidden; margin-top: 8px;">Generating diff...</div>
            </div>
          </div>

          <div class="finding-tool-tag">Scanner: ${vuln.tool_source}</div>
        </div>
      </div>
    `;
  });
  
  docElements.findingsList.innerHTML = html;
  feather.replace();
}

function toggleFinding(vulnId) {
  const item = document.getElementById(`vuln-${vulnId}`);
  item.classList.toggle('open');
}

function escapeHTML(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function previewAutoFix(vulnId, event) {
  if (event) event.stopPropagation();
  
  const statusBadge = document.getElementById(`fix-status-${vulnId}`);
  const previewArea = document.getElementById(`preview-area-${vulnId}`);
  const diffBlock = document.getElementById(`diff-block-${vulnId}`);
  const scanId = currentState.activeScanId;
  
  statusBadge.className = 'fix-status-badge fixing';
  statusBadge.textContent = 'Generating Diff...';
  previewArea.classList.remove('hidden');
  diffBlock.textContent = 'Contacting AI engines...';
  
  try {
    const response = await fetch(`/api/vulnerabilities/${vulnId}/fix?scan_id=${scanId}`, {
      method: 'POST'
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.status === 'no_fix_available') {
        statusBadge.className = 'fix-status-badge failed';
        statusBadge.textContent = 'No Fix Available';
        diffBlock.textContent = 'The AI model could not generate an automated fix for this category of vulnerability.';
      } else if (data.diff) {
        statusBadge.className = 'fix-status-badge ready';
        statusBadge.textContent = 'Diff Ready';
        
        diffBlock.innerHTML = '';
        diffBlock.textContent = '';
        
        if (data.original_code !== undefined && data.original_code !== null && data.fixed_code !== undefined && data.fixed_code !== null) {
          require(['vs/editor/editor.main'], function () {
            let language = 'javascript';
            const vuln = currentState.vulnerabilities.find(v => v.id === vulnId);
            if (vuln && vuln.file_path) {
              const ext = vuln.file_path.split('.').pop().toLowerCase();
              if (ext === 'py') language = 'python';
              else if (ext === 'js') language = 'javascript';
              else if (ext === 'ts') language = 'typescript';
              else if (ext === 'json') language = 'json';
              else if (ext === 'html') language = 'html';
              else if (ext === 'css') language = 'css';
              else if (ext === 'go') language = 'go';
              else if (ext === 'java') language = 'java';
              else if (ext === 'sh') language = 'shell';
            }
            
            const diffEditor = monaco.editor.createDiffEditor(diffBlock, {
              theme: 'vs-dark',
              readOnly: true,
              automaticLayout: true,
              renderSideBySide: true
            });
            
            const originalModel = monaco.editor.createModel(data.original_code, language);
            const modifiedModel = monaco.editor.createModel(data.fixed_code, language);
            
            diffEditor.setModel({
              original: originalModel,
              modified: modifiedModel
            });
          });
        } else {
          // Fallback to text diff display if raw code blocks aren't available
          const diffLines = data.diff.split('\n');
          let diffHtml = '';
          diffLines.forEach(line => {
            if (line.startsWith('+') && !line.startsWith('+++')) {
              diffHtml += `<div class="diff-added" style="color: var(--color-low); background: rgba(16, 185, 129, 0.1); padding: 2px 4px; font-family: monospace;">${escapeHTML(line)}</div>`;
            } else if (line.startsWith('-') && !line.startsWith('---')) {
              diffHtml += `<div class="diff-removed" style="color: var(--color-critical); background: rgba(239, 68, 68, 0.1); padding: 2px 4px; font-family: monospace;">${escapeHTML(line)}</div>`;
            } else {
              diffHtml += `<div style="padding: 2px 4px; font-family: monospace; white-space: pre-wrap;">${escapeHTML(line)}</div>`;
            }
          });
          diffBlock.innerHTML = diffHtml;
        }
      } else {
        statusBadge.className = 'fix-status-badge failed';
        statusBadge.textContent = 'Failed';
        diffBlock.textContent = 'No diff was returned by the engine.';
      }
    } else {
      const err = await response.json();
      statusBadge.className = 'fix-status-badge failed';
      statusBadge.textContent = 'Failed';
      diffBlock.textContent = `Error: ${err.detail || 'Could not fetch fix diff'}`;
    }
  } catch (error) {
    statusBadge.className = 'fix-status-badge failed';
    statusBadge.textContent = 'Failed';
    diffBlock.textContent = `Connection Exception: ${error.message}`;
  }
}

async function applyAutoFix(vulnId, event) {
  if (event) event.stopPropagation();
  
  if (!confirm('Are you sure you want to apply this fix? This will directly patch the source file.')) {
    return;
  }
  
  const statusBadge = document.getElementById(`fix-status-${vulnId}`);
  const applyBtn = document.getElementById(`fix-btn-${vulnId}`);
  const previewBtn = document.getElementById(`preview-btn-${vulnId}`);
  const previewArea = document.getElementById(`preview-area-${vulnId}`);
  const diffBlock = document.getElementById(`diff-block-${vulnId}`);
  const scanId = currentState.activeScanId;
  
  statusBadge.className = 'fix-status-badge fixing';
  statusBadge.textContent = 'Applying...';
  applyBtn.disabled = true;
  previewBtn.disabled = true;
  
  try {
    const response = await fetch(`/api/vulnerabilities/${vulnId}/fix/apply?scan_id=${scanId}`, {
      method: 'POST'
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.success) {
        statusBadge.className = 'fix-status-badge success';
        statusBadge.textContent = 'Fixed';
        
        previewArea.classList.remove('hidden');
        diffBlock.innerHTML = '<span class="diff-added">✓ Security patch applied successfully to file. Code has been rewritten.</span>';
        
        // Update local state is_fixed to true so it persists if filters are applied
        const vuln = currentState.vulnerabilities.find(v => v.id === vulnId);
        if (vuln) {
          vuln.is_fixed = true;
        }
        
        // Optionally update dashboard summary stats without full reload
        loadHistory();
      } else {
        statusBadge.className = 'fix-status-badge failed';
        statusBadge.textContent = 'Failed';
        applyBtn.disabled = false;
        previewBtn.disabled = false;
        alert(`Failed to apply fix: ${data.error || 'Syntax validation failed'}`);
      }
    } else {
      const err = await response.json();
      statusBadge.className = 'fix-status-badge failed';
      statusBadge.textContent = 'Failed';
      applyBtn.disabled = false;
      previewBtn.disabled = false;
      alert(`API Error: ${err.detail || 'Failed to apply patch'}`);
    }
  } catch (error) {
    statusBadge.className = 'fix-status-badge failed';
    statusBadge.textContent = 'Failed';
    applyBtn.disabled = false;
    previewBtn.disabled = false;
    alert(`Connection Exception: ${error.message}`);
  }
}

function renderAnalyticsCharts(results) {
  if (typeof Chart === 'undefined') {
    console.warn("Chart.js is not loaded.");
    return;
  }

  if (severityChartInstance) {
    severityChartInstance.destroy();
  }
  if (categoryChartInstance) {
    categoryChartInstance.destroy();
  }
  
  const stats = results.stats || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const isLightTheme = document.documentElement.getAttribute('data-theme') === 'light';
  const textColor = isLightTheme ? '#111827' : '#ffffff';
  
  // 1. Severity Distribution Chart (Pie/Doughnut)
  const sevCanvas = document.getElementById('severity-chart');
  if (sevCanvas) {
    const sevCtx = sevCanvas.getContext('2d');
    severityChartInstance = new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: [
            stats.critical || 0,
            stats.high || 0,
            stats.medium || 0,
            stats.low || 0,
            stats.info || 0
          ],
          backgroundColor: [
            '#ef4444', // critical
            '#f97316', // high
            '#f59e0b', // medium
            '#10b981', // low
            '#3b82f6'  // info
          ],
          borderWidth: 1,
          borderColor: isLightTheme ? '#ffffff' : '#121420'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: textColor,
              font: { family: 'Inter', size: 11 }
            }
          }
        }
      }
    });
  }

  // 2. Category Distribution Chart (Bar)
  const categoryCounts = {};
  (results.vulnerabilities || []).forEach(v => {
    categoryCounts[v.category] = (categoryCounts[v.category] || 0) + 1;
  });
  
  const categories = Object.keys(categoryCounts);
  const counts = Object.values(categoryCounts);
  
  const catCanvas = document.getElementById('category-chart');
  if (catCanvas && categories.length > 0) {
    const catCtx = catCanvas.getContext('2d');
    categoryChartInstance = new Chart(catCtx, {
      type: 'bar',
      data: {
        labels: categories,
        datasets: [{
          label: 'Issues Count',
          data: counts,
          backgroundColor: 'rgba(99, 102, 241, 0.7)',
          borderColor: '#6366f1',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: textColor,
              font: { family: 'Inter', size: 10 }
            }
          },
          y: {
            grid: { color: isLightTheme ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.05)' },
            ticks: {
              color: textColor,
              font: { family: 'Inter', size: 10 },
              stepSize: 1
            }
          }
        }
      }
    });
  }
}

function renderSwarmNetworkGraph(percent, scanStatus) {
  const container = document.getElementById('swarm-network-graph');
  if (!container) return;

  const nodes = [
    { id: 'john', name: 'John (SAST)', x: 60, y: 35, range: [10, 60] },
    { id: 'sam', name: 'Sam (Secrets)', x: 60, y: 90, range: [15, 60] },
    { id: 'pam', name: 'Pam (SCA)', x: 60, y: 145, range: [20, 60] },
    { id: 'tina', name: 'Tina (Taint)', x: 170, y: 90, range: [60, 80] },
    { id: 'triager', name: 'Triager', x: 280, y: 90, range: [80, 90] },
    { id: 'fixer', name: 'Fixer', x: 390, y: 90, range: [90, 95] },
    { id: 'assembler', name: 'Assembler', x: 490, y: 90, range: [95, 100] }
  ];

  // Helper to determine status color
  const getStatusColor = (agent) => {
    if (scanStatus === 'completed') return '#10b981'; // Done
    if (scanStatus === 'failed') {
      if (percent >= agent.range[0] && percent < agent.range[1]) return '#ef4444'; // Failed
      if (percent >= agent.range[1]) return '#10b981'; // Done
      return '#4b5563'; // Pending
    }
    if (percent < agent.range[0]) return '#4b5563'; // Pending
    if (percent >= agent.range[0] && percent < agent.range[1]) return '#6366f1'; // Active
    return '#10b981'; // Done
  };

  // Helper to determine if link is active
  const isLinkActive = (fromNode, toNode) => {
    if (scanStatus !== 'running') return false;
    // Check if the current progress phase matches the connection
    if (fromNode.id === 'john' || fromNode.id === 'sam' || fromNode.id === 'pam') {
      return percent >= 10 && percent < 60;
    }
    if (fromNode.id === 'tina') return percent >= 60 && percent < 80;
    if (fromNode.id === 'triager') return percent >= 80 && percent < 90;
    if (fromNode.id === 'fixer') return percent >= 90 && percent < 95;
    return false;
  };

  let linksHtml = '';
  let pulsesHtml = '';
  
  // Render Links and Animated Pulses
  const connections = [
    { from: 'john', to: 'tina' },
    { from: 'sam', to: 'tina' },
    { from: 'pam', to: 'tina' },
    { from: 'tina', to: 'triager' },
    { from: 'triager', to: 'fixer' },
    { from: 'fixer', to: 'assembler' }
  ];

  connections.forEach((conn) => {
    const fromNode = nodes.find(n => n.id === conn.from);
    const toNode = nodes.find(n => n.id === conn.to);
    const active = isLinkActive(fromNode, toNode);
    const color = active ? '#6366f1' : 'rgba(255, 255, 255, 0.08)';
    const strokeDash = active ? 'stroke-dasharray="4, 2" class="anim-dash"' : '';
    
    linksHtml += `<line x1="${fromNode.x}" y1="${fromNode.y}" x2="${toNode.x}" y2="${toNode.y}" stroke="${color}" stroke-width="1.5" ${strokeDash} />`;
    
    if (active) {
      pulsesHtml += `
        <circle r="3.5" fill="#6366f1" opacity="0.9">
          <animateMotion dur="1.8s" repeatCount="indefinite"
            path="M ${fromNode.x} ${fromNode.y} L ${toNode.x} ${toNode.y}" />
        </circle>
      `;
    }
  });

  let nodesHtml = '';
  nodes.forEach(node => {
    const color = getStatusColor(node);
    const isActive = scanStatus === 'running' && percent >= node.range[0] && percent < node.range[1];
    
    // Glowing ring for active node
    const glowHtml = isActive ? `
      <circle cx="${node.x}" cy="${node.y}" r="15" fill="none" stroke="#6366f1" stroke-width="2" opacity="0.8">
        <animate attributeName="r" values="8;18;8" dur="1.5s" repeatCount="indefinite" />
        <animate attributeName="opacity" values="0.8;0;0.8" dur="1.5s" repeatCount="indefinite" />
      </circle>
    ` : '';
    
    nodesHtml += `
      <g>
        ${glowHtml}
        <circle cx="${node.x}" cy="${node.y}" r="8" fill="${color}" stroke="rgba(255,255,255,0.15)" stroke-width="2" />
        <text x="${node.x}" y="${node.y - 14}" text-anchor="middle" fill="var(--color-text-muted)" font-family="Inter" font-size="9" font-weight="600">${node.name}</text>
      </g>
    `;
  });

  const svg = `
    <svg width="100%" height="100%" viewBox="0 0 540 180" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <style>
          .anim-dash {
            animation: dash 1s linear infinite;
          }
          @keyframes dash {
            to {
              stroke-dashoffset: -6;
            }
          }
        </style>
      </defs>
      ${linksHtml}
      ${pulsesHtml}
      ${nodesHtml}
    </svg>
  `;

  container.innerHTML = svg;
}

async function openInMonacoEditor(vulnId, event) {
  if (event) event.stopPropagation();
  
  const vuln = currentState.vulnerabilities.find(v => v.id === vulnId);
  if (!vuln) return;
  
  const scanId = currentState.activeScanId;
  const filePath = vuln.file_path;
  currentEditingFilePath = filePath;
  
  document.getElementById('editor-filename').textContent = filePath.split('/').pop();
  document.getElementById('editor-filepath').textContent = filePath;
  
  const overlay = document.getElementById('editor-overlay');
  overlay.classList.remove('hidden');
  
  const container = document.getElementById('monaco-editor-container');
  container.innerHTML = '';
  
  try {
    const response = await fetch(`/api/scan/${scanId}/file?file_path=${encodeURIComponent(filePath)}`);
    if (response.ok) {
      const data = await response.json();
      
      require(['vs/editor/editor.main'], function () {
        let language = 'javascript';
        const ext = filePath.split('.').pop().toLowerCase();
        if (ext === 'py') language = 'python';
        else if (ext === 'js') language = 'javascript';
        else if (ext === 'ts') language = 'typescript';
        else if (ext === 'json') language = 'json';
        else if (ext === 'html') language = 'html';
        else if (ext === 'css') language = 'css';
        else if (ext === 'go') language = 'go';
        else if (ext === 'java') language = 'java';
        else if (ext === 'sh') language = 'shell';
        
        monacoEditorInstance = monaco.editor.create(container, {
          value: data.content || '',
          language: language,
          theme: 'vs-dark',
          automaticLayout: true
        });
      });
    } else {
      alert("Failed to fetch file content.");
    }
  } catch (err) {
    alert("Connection error: " + err.message);
  }
}

