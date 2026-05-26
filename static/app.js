// Global State
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
let pollingInterval = null;

function startPolling(scanId) {
  if (pollingInterval) clearInterval(pollingInterval);
  
  updateProgress(0, 'Initializing...', 'running');
  
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
        else if (progress < 95) phase = 'Deduplicating vulnerability findings...';
        else if (progress === 100) phase = 'Completed';
        
        if (status === 'failed') {
          phase = 'Scan Failed';
          showLog(`Error encountered: ${data.error || 'Unknown scanner error'}`, 'error');
        } else {
          showLog(`Progress updated: ${progress}% - ${phase}`);
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
        // Tolerating temporary backend network glitch/404s
        showLog('Polling backend... waiting for record to sync', 'warn');
      }
    } catch (error) {
      showLog(`Status fetch exception: ${error.message}`, 'warn');
    }
  }, 2500);
}

function updateProgress(percent, phaseText, status) {
  docElements.progressPhase.textContent = phaseText;
  docElements.progressPercent.textContent = `${percent}%`;
  docElements.progressBarFill.style.width = `${percent}%`;
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
            </div>
            <div class="fix-preview-area hidden" id="preview-area-${vuln.id}">
              <h5>Proposed Diff:</h5>
              <pre class="diff-block" id="diff-block-${vuln.id}">Generating diff...</pre>
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
        
        // Formatter for diff block to color additions/deletions
        const diffLines = data.diff.split('\n');
        let diffHtml = '';
        diffLines.forEach(line => {
          if (line.startsWith('+') && !line.startsWith('+++')) {
            diffHtml += `<span class="diff-added">${escapeHTML(line)}</span>`;
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            diffHtml += `<span class="diff-removed">${escapeHTML(line)}</span>`;
          } else {
            diffHtml += `<span>${escapeHTML(line)}</span>\n`;
          }
        });
        diffBlock.innerHTML = diffHtml;
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
