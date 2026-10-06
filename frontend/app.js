/**
 * app.js — Frontend Client Logic for AI Policy Layer Platform
 */

const API_BASE = '';

// DOM Helpers
function $(id) {
  return document.getElementById(id);
}

function escapeHtml(str) {
  if (typeof str !== 'string') {
    str = JSON.stringify(str, null, 2) || '';
  }
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function requestApi(endpoint, options = {}) {
  try {
    const res = await fetch(API_BASE + endpoint, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Server returned ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (err) {
    console.error(`API Error on ${endpoint}:`, err);
    throw err;
  }
}

// ════════════ INITIALIZATION ════════════
document.addEventListener('DOMContentLoaded', () => {
  checkHealth();
  loadSandboxFiles();
  loadApprovals();
  loadAuditLedger();
});

async function checkHealth() {
  try {
    const health = await requestApi('/api/health');
    $('backendStatus').textContent = 'Online';
    $('envKeyStatus').textContent = health.has_env_key ? 'Loaded (.env)' : 'Missing';
    $('activeModel').textContent = health.default_model;
  } catch (err) {
    $('backendStatus').textContent = 'Offline';
    $('backendStatus').style.color = '#ef4444';
  }
}

function setPreset(text) {
  $('promptInput').value = text;
  $('promptInput').focus();
  runComparison();
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

  event.currentTarget.classList.add('active');
  $(tabId).classList.add('active');

  if (tabId === 'auditTab') loadAuditLedger();
  if (tabId === 'sandboxTab') loadSandboxFiles();
}

// ════════════ MAIN RUN COMPARISON ════════════
async function runComparison() {
  const prompt = $('promptInput').value.trim();
  if (!prompt) {
    $('promptInput').focus();
    return;
  }

  const model = $('modelSelect').value;
  const runBtn = $('runBtn');
  const runBtnText = $('runBtnText');
  const runSpinner = $('runSpinner');

  // Set Loading UI
  runBtn.disabled = true;
  runBtnText.textContent = 'Evaluating...';
  runSpinner.style.display = 'inline-block';

  $('directPanelBody').innerHTML = `
    <div class="loading-box">
      <div class="spinner"></div>
      <div class="loading-text">Executing directly without Policy Layer...</div>
    </div>
  `;

  $('governedPanelBody').innerHTML = `
    <div class="loading-box">
      <div class="spinner"></div>
      <div class="loading-text">Intercepting, Snapshotting & Judging Action...</div>
    </div>
  `;

  const payload = JSON.stringify({ prompt, model });

  try {
    // Run both agents in parallel
    const [directRes, governedRes] = await Promise.allSettled([
      requestApi('/api/direct/execute', { method: 'POST', body: payload }),
      requestApi('/api/governed/execute', { method: 'POST', body: payload }),
    ]);

    const directData = directRes.status === 'fulfilled' ? directRes.value : { success: false, error: directRes.reason.message };
    const governedData = governedRes.status === 'fulfilled' ? governedRes.value : { success: false, error: governedRes.reason.message };

    renderDirectPanel(directData);
    renderGovernedPanel(governedData);
    renderScorecard(directData, governedData);

  } finally {
    runBtn.disabled = false;
    runBtnText.textContent = 'Run Both Agents';
    runSpinner.style.display = 'none';

    // Refresh supplementary state
    loadApprovals();
    loadAuditLedger();
    loadSandboxFiles();
  }
}

// ════════════ RENDER DIRECT AGENT PANEL ════════════
function renderDirectPanel(data) {
  const container = $('directPanelBody');

  if (!data.success) {
    container.innerHTML = `
      <div class="vulnerability-alert-box">
        <span>❌</span> <strong>Execution Failed:</strong> ${escapeHtml(data.error || 'Unknown error')}
      </div>
    `;
    return;
  }

  let html = '<div class="execution-flow">';

  const toolCalls = data.tool_calls || [];
  if (toolCalls.length === 0) {
    html += `
      <div class="flow-step-card">
        <div class="step-card-header">
          <span class="step-tag-pill pill-blue">LLM DIRECT ANSWER</span>
          <span>No Tool Calls Required</span>
        </div>
        <div class="step-card-body">
          <p class="final-response-text">${escapeHtml(data.agent_response)}</p>
        </div>
      </div>
    `;
  } else {
    // 1. Pipeline Sequence Ribbon at top
    const stepsSummary = toolCalls.map((tc, i) => {
      const isDangerous = tc.is_dangerous;
      return `<span style="color:${isDangerous ? '#f87171' : '#93c5fd'}">Step ${i + 1}: <code>${escapeHtml(tc.tool)}</code> ${isDangerous ? '[⚠️ DIRECT]' : '[OK]'}</span>`;
    }).join(' ➔ ');
    html += `<div class="sequence-ribbon">📍 <strong>Execution Path:</strong> ${stepsSummary}</div>`;

    // 2. High-Risk Warning Banner if any dangerous action occurred
    const dangerousCalls = toolCalls.filter(tc => tc.is_dangerous);
    if (dangerousCalls.length > 0) {
      const dc = dangerousCalls[0];
      html += `
        <div class="unprotected-banner">
          <div class="unprotected-badge">🚨 ZERO GUARDRAILS DETECTED</div>
          <div class="unprotected-title">Unprotected Tool: <code>${escapeHtml(dc.tool)}(${escapeHtml(JSON.stringify(dc.args))})</code></div>
          <div class="unprotected-desc">${escapeHtml(dc.vulnerability_flag || 'Direct execution without policy verification.')}</div>
        </div>
      `;
    }

    // 3. Render Each Step
    toolCalls.forEach((tc, idx) => {
      const isDangerous = tc.is_dangerous;
      const pillClass = isDangerous ? 'pill-danger' : 'pill-warn';

      html += `
        <div class="flow-step-card">
          <div class="step-card-header">
            <div class="step-title-group">
              <span class="step-tag-pill ${pillClass}">STEP ${idx + 1} OF ${toolCalls.length}: ${tc.tool}</span>
            </div>
            <span class="badge ${isDangerous ? 'badge-unprotected' : 'badge-warn'}">
              ${isDangerous ? 'DANGEROUS ACTION' : 'DIRECT CALL'}
            </span>
          </div>

          <div class="step-card-body">
            <div class="action-signature">
              <strong>Invoked:</strong> <code>${escapeHtml(tc.tool)}(${escapeHtml(JSON.stringify(tc.args))})</code>
            </div>

            ${isDangerous ? `
              <div class="vulnerability-alert-box">
                <span>🚨</span> <strong>CRITICAL SECURITY RISK:</strong> ${escapeHtml(tc.vulnerability_flag || 'Zero boundary enforcement')}
              </div>
            ` : ''}

            <!-- Compact File List Format to prevent massive scrollbars -->
            ${tc.tool === 'list_files' && tc.result && tc.result.files ? `
              <div class="result-summary-box">
                📁 <strong>Found ${tc.result.files.length} Sandbox Files:</strong>
                <span class="mono">${escapeHtml(tc.result.files.map(f => f.name).join(', '))}</span>
                <details style="margin-top:6px; cursor:pointer;">
                  <summary style="font-size:0.75rem; color:var(--accent-cyan)">View Raw JSON</summary>
                  <div class="result-code-box">${escapeHtml(JSON.stringify(tc.result, null, 2))}</div>
                </details>
              </div>
            ` : tc.result ? `
              <div class="result-code-box">${escapeHtml(JSON.stringify(tc.result, null, 2))}</div>
            ` : ''}
          </div>
        </div>
      `;
    });

    if (data.agent_response) {
      html += `
        <div class="final-response-box">
          <div class="final-response-header">
            <span>🤖</span> Direct Agent Final Answer (Unprotected)
          </div>
          <div class="final-response-text">${escapeHtml(data.agent_response)}</div>
        </div>
      `;
    }
  }

  html += '</div>';
  container.innerHTML = html;
}

// ════════════ RENDER GOVERNED AGENT PANEL ════════════
function renderGovernedPanel(data) {
  const container = $('governedPanelBody');

  if (!data.success) {
    container.innerHTML = `
      <div class="vulnerability-alert-box">
        <span>❌</span> <strong>Governance Engine Error:</strong> ${escapeHtml(data.error || 'Unknown error')}
      </div>
    `;
    return;
  }

  let html = '<div class="execution-flow">';

  const trace = data.policy_trace || [];
  if (trace.length === 0) {
    html += `
      <div class="flow-step-card">
        <div class="step-card-header">
          <span class="step-tag-pill pill-success">POLICY CLEARANCE</span>
          <span>Benign Query</span>
        </div>
        <div class="step-card-body">
          <p class="final-response-text">${escapeHtml(data.agent_response)}</p>
        </div>
      </div>
    `;
  } else {
    // 1. Pipeline Sequence Ribbon at top
    const stepsSummary = trace.map((st, i) => {
      const v = st.policy_decision?.verdict || 'EVAL';
      const icon = v === 'DENY' ? '🛑' : v === 'ASK_USER' ? '🎫' : '✅';
      const color = v === 'DENY' ? '#ef4444' : v === 'ASK_USER' ? '#f59e0b' : '#10b981';
      return `<span style="color:${color}">Step ${i + 1}: <code>${escapeHtml(st.tool)}</code> [${icon} ${v}]</span>`;
    }).join(' ➔ ');
    html += `<div class="sequence-ribbon">📍 <strong>Governance Path:</strong> ${stepsSummary}</div>`;

    // 2. High-Profile Quarantine Banner at top if ANY action was DENIED
    const deniedSteps = trace.filter(st => st.policy_decision?.verdict === 'DENY');
    if (deniedSteps.length > 0) {
      const ds = deniedSteps[0];
      html += `
        <div class="quarantine-banner">
          <div class="quarantine-badge">🛡️ THREAT QUARANTINED BY POLICY LAYER</div>
          <div class="quarantine-title">Blocked Tool: <code>${escapeHtml(ds.tool)}(${escapeHtml(JSON.stringify(ds.args))})</code></div>
          <div class="quarantine-desc">${escapeHtml(ds.policy_decision?.reason || 'Quarantined under enterprise security policy.')}</div>
        </div>
      `;
    }

    // 3. Render Each Step in Governance Flow
    trace.forEach((step, idx) => {
      const decision = step.policy_decision || {};
      const verdict = decision.verdict || 'UNKNOWN';
      const snap = step.snapshot || {};
      const risk = decision.risk_score || 0.0;

      let verdictBadgeClass = 'badge-protected';
      let pillClass = 'pill-success';
      let verdictIcon = '✅';

      if (verdict === 'DENY') {
        verdictBadgeClass = 'badge-unprotected';
        pillClass = 'pill-danger';
        verdictIcon = '🛑';
      } else if (verdict === 'ASK_USER') {
        verdictBadgeClass = 'badge-warn';
        pillClass = 'pill-warn';
        verdictIcon = '🎫';
      }

      const riskPct = Math.round(risk * 100);
      const riskFillClass = riskPct > 70 ? 'fill-high' : riskPct > 30 ? 'fill-med' : 'fill-low';

      html += `
        <div class="flow-step-card" style="${verdict === 'DENY' ? 'border-color: rgba(239, 68, 68, 0.4);' : ''}">
          <div class="step-card-header">
            <div class="step-title-group">
              <span class="step-tag-pill ${pillClass}">STEP ${idx + 1} OF ${trace.length}: ${verdictIcon} ${verdict}</span>
              <span>${escapeHtml(step.tool)}</span>
            </div>
            <span class="badge ${verdictBadgeClass}">
              POLICY: ${escapeHtml(decision.rule || 'RULE_EVAL')}
            </span>
          </div>

          <div class="step-card-body">
            <div class="action-signature">
              <strong>Proposed:</strong> <code>${escapeHtml(step.tool)}(${escapeHtml(JSON.stringify(step.args))})</code>
            </div>

            <!-- SNAPSHOT & HASH -->
            <div class="pipeline-badges">
              <span class="pipeline-badge">📸 <strong>ID:</strong> ${escapeHtml(snap.snapshot_id || 'N/A')}</span>
              <span class="pipeline-badge">🔐 <strong>SHA-256:</strong> ${escapeHtml(snap.hash || 'Verified')}</span>
              <span class="pipeline-badge">🛡️ <strong>Rule:</strong> ${escapeHtml(decision.rule || 'N/A')}</span>
            </div>

            <!-- RISK METER -->
            <div class="risk-meter">
              <span style="color:var(--text-dim)">Calculated Risk:</span>
              <div class="risk-bar-track">
                <div class="risk-bar-fill ${riskFillClass}" style="width: ${riskPct}%"></div>
              </div>
              <span style="font-family:var(--font-mono)">${riskPct}%</span>
            </div>

            <!-- VERDICT DETAILS -->
            ${verdict === 'DENY' ? `
              <div class="policy-block-box">
                <div class="policy-block-title">
                  <span>🛑</span> ACTION QUARANTINED BY POLICY JUDGE LLM
                </div>
                <div>${escapeHtml(decision.reason)}</div>
                ${decision.mitigation ? `<div style="margin-top:6px; color:#cbd5e1; font-size:0.75rem;">💡 <em>Mitigation: ${escapeHtml(decision.mitigation)}</em></div>` : ''}
              </div>
            ` : ''}

            ${verdict === 'ASK_USER' ? `
              <div class="vulnerability-alert-box" style="background:var(--color-warn-bg); border-color:var(--color-warn-border); color:#fde68a;">
                <span>🎫</span> <strong>HUMAN APPROVAL TICKET CREATED:</strong> ${escapeHtml(step.ticket_id || 'Queued')}
                <div style="font-size:0.75rem; margin-top:4px;">${escapeHtml(decision.reason)}</div>
              </div>
            ` : ''}

            <!-- Compact File List to prevent pushing blocks off-screen -->
            ${step.tool === 'list_files' && step.result && step.result.files ? `
              <div class="result-summary-box">
                📁 <strong>Listed ${step.result.files.length} Sandbox Files:</strong>
                <span class="mono">${escapeHtml(step.result.files.map(f => f.name).join(', '))}</span>
                <details style="margin-top:6px; cursor:pointer;">
                  <summary style="font-size:0.75rem; color:var(--accent-cyan)">View Raw JSON</summary>
                  <div class="result-code-box">${escapeHtml(JSON.stringify(step.result, null, 2))}</div>
                </details>
              </div>
            ` : step.executed && step.result ? `
              <div class="result-code-box">${escapeHtml(JSON.stringify(step.result, null, 2))}</div>
            ` : ''}
          </div>
        </div>
      `;
    });

    if (data.agent_response) {
      html += `
        <div class="final-response-box" style="border-color: rgba(16, 185, 129, 0.3); background: rgba(16, 185, 129, 0.05);">
          <div class="final-response-header" style="color:#34d399;">
            <span>🛡️</span> Governed Agent Final Synthesis
          </div>
          <div class="final-response-text">${escapeHtml(data.agent_response)}</div>
        </div>
      `;
    }
  }

  html += '</div>';
  container.innerHTML = html;
}

// ════════════ DYNAMIC SCORECARD ════════════
function renderScorecard(directData, governedData) {
  const scorecard = $('scorecardSection');
  scorecard.style.display = 'block';

  let directThreats = 0;
  if (directData.tool_calls) {
    directThreats = directData.tool_calls.filter(tc => tc.is_dangerous).length;
  }

  let governedBlocked = 0;
  let governedApproved = 0;
  if (governedData.policy_trace) {
    governedBlocked = governedData.policy_trace.filter(s => s.policy_decision && s.policy_decision.verdict === 'DENY').length;
    governedApproved = governedData.policy_trace.filter(s => s.policy_decision && s.policy_decision.verdict === 'ASK_USER').length;
  }

  if (directThreats > 0) {
    $('directPosture').textContent = `Compromised (${directThreats} Critical Risk Leaked)`;
    $('directPosture').className = 'metric-val text-danger';
  } else {
    $('directPosture').textContent = 'Executed Blindly (No Guardrail)';
    $('directPosture').className = 'metric-val text-danger';
  }

  if (governedBlocked > 0) {
    $('governedPosture').textContent = `Enforced (${governedBlocked} Threat Neutralized)`;
    $('governedPosture').className = 'metric-val text-success';
    $('scorecardBadge').textContent = 'Threat Quarantined';
    $('scorecardBadge').style.background = 'rgba(16, 185, 129, 0.2)';
    $('scorecardBadge').style.borderColor = '#10b981';
  } else if (governedApproved > 0) {
    $('governedPosture').textContent = `Gated (${governedApproved} Awaiting Approval)`;
    $('governedPosture').className = 'metric-val text-warn';
    $('scorecardBadge').textContent = 'Pending Human Sign-off';
    $('scorecardBadge').style.background = 'rgba(245, 158, 11, 0.2)';
    $('scorecardBadge').style.borderColor = '#f59e0b';
  } else {
    $('governedPosture').textContent = 'Validated Safe';
    $('governedPosture').className = 'metric-val text-success';
    $('scorecardBadge').textContent = 'Policy Cleared';
  }
}

// ════════════ APPROVAL WORKFLOW ════════════
async function loadApprovals() {
  try {
    const data = await requestApi('/api/approvals');
    const pending = data.pending || [];
    const section = $('approvalSection');
    const container = $('approvalTicketList');

    $('ticketCount').textContent = pending.length;

    if (pending.length === 0) {
      section.style.display = 'none';
      return;
    }

    section.style.display = 'block';
    let html = '';

    pending.forEach(t => {
      const snap = t.snapshot || {};
      const dec = t.decision || {};

      html += `
        <div class="ticket-card" id="card-${t.ticket_id}">
          <div class="ticket-header">
            <div class="ticket-title">⚠️ Action Requires Human Authorization: ${escapeHtml(snap.tool)}</div>
            <div class="ticket-id">TICKET: ${escapeHtml(t.ticket_id)}</div>
          </div>
          <div class="ticket-body">
            <div class="ticket-meta-grid">
              <div><strong>Tool:</strong> ${escapeHtml(snap.tool)}</div>
              <div><strong>Args:</strong> ${escapeHtml(JSON.stringify(snap.args))}</div>
              <div><strong>Rule:</strong> ${escapeHtml(dec.rule)}</div>
              <div><strong>Snapshot Hash:</strong> ${escapeHtml(snap.hash)}</div>
            </div>
            <p><strong>Reason:</strong> ${escapeHtml(dec.reason)}</p>
          </div>
          <div class="ticket-actions">
            <button class="btn btn-approve" onclick="resolveTicket('${t.ticket_id}', true)">
              ✅ Approve & Execute (with Revalidation)
            </button>
            <button class="btn btn-reject" onclick="resolveTicket('${t.ticket_id}', false)">
              ❌ Reject & Block
            </button>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  } catch (err) {
    console.error('Failed to load approvals:', err);
  }
}

async function resolveTicket(ticketId, approved) {
  try {
    const res = await requestApi('/api/approvals/resolve', {
      method: 'POST',
      body: JSON.stringify({ ticket_id: ticketId, approved, comment: 'Operator review in UI' }),
    });

    alert(
      approved
        ? `Ticket ${ticketId} APPROVED!\nRevalidation: ${res.revalidation ? res.revalidation.message : 'OK'}\nResult: ${JSON.stringify(res.execution_result)}`
        : `Ticket ${ticketId} REJECTED.`
    );

    loadApprovals();
    loadAuditLedger();
    loadSandboxFiles();
  } catch (err) {
    alert(`Error resolving ticket: ${err.message}`);
  }
}

// ════════════ SANDBOX EXPLORER ════════════
async function loadSandboxFiles() {
  const grid = $('sandboxFilesGrid');
  try {
    const data = await requestApi('/api/sandbox/files');
    const files = data.files || [];

    let html = '';
    files.forEach(f => {
      const isRestricted = f.name.includes('.env') || f.name.includes('id_rsa') || f.name.includes('production_db');
      const icon = isRestricted ? '🔒' : f.name.endsWith('.csv') ? '📊' : f.name.endsWith('.json') ? '⚙️' : '📄';

      html += `
        <div class="file-card" onclick="previewFile('${escapeHtml(f.name)}')">
          <div class="file-info">
            <span class="file-icon">${icon}</span>
            <div>
              <div class="file-name">${escapeHtml(f.name)}</div>
              <div class="file-size">${f.size} bytes ${isRestricted ? '• <span style="color:#f87171">DLP Protected</span>' : ''}</div>
            </div>
          </div>
          <span style="font-size:0.75rem; color:var(--text-dim)">Inspect ➔</span>
        </div>
      `;
    });

    grid.innerHTML = html;
  } catch (err) {
    grid.innerHTML = `<div class="vulnerability-alert-box">Error loading files: ${err.message}</div>`;
  }
}

async function previewFile(path) {
  try {
    const res = await requestApi(`/api/sandbox/file-content?path=${encodeURIComponent(path)}`);
    const previewCard = $('filePreviewCard');
    const pathLabel = $('previewFilePath');
    const badge = $('previewBadge');
    const content = $('previewFileContent');

    pathLabel.textContent = path;
    const isRestricted = path.includes('.env') || path.includes('id_rsa') || path.includes('production_db');

    if (isRestricted) {
      badge.textContent = 'RESTRICTED DLP ASSET';
      badge.className = 'badge badge-danger';
    } else {
      badge.textContent = 'PUBLIC SANDBOX ASSET';
      badge.className = 'badge badge-protected';
    }

    content.textContent = res.content || JSON.stringify(res, null, 2);
    previewCard.style.display = 'block';
  } catch (err) {
    alert(`Could not read file: ${err.message}`);
  }
}

function closeFilePreview() {
  $('filePreviewCard').style.display = 'none';
}

// ════════════ AUDIT LEDGER ════════════
async function loadAuditLedger() {
  try {
    const data = await requestApi('/api/audit');
    const tbody = $('auditTableBody');
    const entries = data.entries || [];

    if (entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding:20px; color:var(--text-dim)">No audit entries recorded yet.</td></tr>';
      return;
    }

    let html = '';
    entries.forEach(e => {
      const v = e.verdict;
      const vClass = v === 'DENY' ? 'pill-danger' : v === 'ASK_USER' ? 'pill-warn' : 'pill-success';

      html += `
        <tr>
          <td>${new Date(e.timestamp).toLocaleTimeString()}</td>
          <td style="color:#93c5fd">${escapeHtml(e.action_hash.slice(0, 12))}...</td>
          <td><strong>${escapeHtml(e.tool)}</strong></td>
          <td><span class="step-tag-pill ${vClass}">${escapeHtml(v)}</span></td>
          <td>${Math.round(e.risk_score * 100)}%</td>
          <td style="color:var(--text-muted)">${escapeHtml(e.rule)}</td>
          <td>${e.executed ? '<span style="color:#34d399">Executed</span>' : '<span style="color:#f87171">Quarantined</span>'}</td>
        </tr>
      `;
    });

    tbody.innerHTML = html;
  } catch (err) {
    console.error('Error loading audit ledger:', err);
  }
}

// ════════════ RESET ENVIRONMENT ════════════
async function resetEnvironment() {
  if (!confirm('Reset sandbox filesystem, transaction totals, and audit logs?')) return;
  try {
    await requestApi('/api/sandbox/reset', { method: 'POST' });
    alert('Environment successfully reset to clean state.');
    closeFilePreview();
    loadSandboxFiles();
    loadApprovals();
    loadAuditLedger();
  } catch (err) {
    alert(`Reset failed: ${err.message}`);
  }
}
