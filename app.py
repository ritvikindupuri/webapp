import os
import json
import logging
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn

import docker_daemon
import ai_forensics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

app = FastAPI(title="Sentinel - Autonomous Container Self-Healing Engine")

class AttackModel(BaseModel):
    container_id: str
    attack_type: str

class HealModel(BaseModel):
    container_id: str

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel — Autonomous Container Self-Healing Engine</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #07090e;
            --bg-surface: #0f1420;
            --bg-card: #161c2e;
            --border: rgba(255, 255, 255, 0.08);
            --primary: #38bdf8;
            --primary-glow: rgba(56, 189, 248, 0.2);
            --accent-amber: #f59e0b;
            --accent-amber-glow: rgba(245, 158, 11, 0.2);
            --safe-green: #10b981;
            --safe-glow: rgba(16, 185, 129, 0.2);
            --danger-red: #ef4444;
            --danger-glow: rgba(239, 68, 68, 0.25);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --terminal-bg: #030712;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Outfit', -apple-system, sans-serif;
            height: 100vh;
            display: flex; flex-direction: column;
            overflow: hidden;
        }

        header {
            background: rgba(11, 15, 25, 0.95);
            backdrop-filter: blur(16px);
            border-bottom: 1px solid var(--border);
            padding: 0.85rem 2rem;
            display: flex; justify-content: space-between; align-items: center;
        }

        .brand { display: flex; align-items: center; gap: 0.75rem; }
        .logo-box {
            width: 34px; height: 34px;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 0 15px var(--primary-glow);
        }

        h1 {
            font-size: 1.35rem; font-weight: 800; letter-spacing: -0.02em;
            background: linear-gradient(135deg, #f8fafc, #cbd5e1);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }

        .engine-badge {
            font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.08em; padding: 0.35rem 0.85rem; border-radius: 20px;
            background: rgba(16, 185, 129, 0.1); color: var(--safe-green);
            border: 1px solid rgba(16, 185, 129, 0.3);
            display: inline-flex; align-items: center; gap: 0.4rem;
        }

        main { flex: 1; display: flex; overflow: hidden; }

        .column { display: flex; flex-direction: column; overflow: hidden; }
        .col-left { flex: 1.15; border-right: 1px solid var(--border); background: var(--bg-surface); }
        .col-right { flex: 0.85; background: var(--bg-base); }

        .section-header {
            padding: 0.9rem 1.75rem;
            border-bottom: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
            background: rgba(7, 9, 14, 0.5);
        }
        .section-title {
            font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.1em; color: var(--text-muted);
        }

        /* Controls Bar */
        .controls-bar {
            padding: 0.85rem 1.75rem;
            background: rgba(15, 20, 32, 0.8);
            border-bottom: 1px solid var(--border);
            display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap;
        }

        .btn-launch {
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: var(--primary);
            padding: 0.45rem 0.95rem; font-size: 0.78rem; font-weight: 700;
            border-radius: 6px; cursor: pointer; transition: all 0.2s ease;
        }
        .btn-launch:hover {
            background: var(--primary); color: #000;
            box-shadow: 0 0 15px var(--primary-glow);
        }

        .sim-btn {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 0.45rem 0.85rem; font-size: 0.76rem; font-weight: 600;
            border-radius: 6px; cursor: pointer; transition: all 0.2s ease;
        }
        .sim-btn:hover {
            color: var(--text-main); border-color: var(--accent-amber);
            background: var(--accent-amber-glow);
        }

        .btn-heal {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white; border: none;
            padding: 0.5rem 1.25rem; font-size: 0.82rem; font-weight: 700;
            border-radius: 6px; cursor: pointer; transition: all 0.2s ease;
            box-shadow: 0 0 15px var(--safe-glow);
            margin-left: auto;
        }
        .btn-heal:hover { opacity: 0.95; box-shadow: 0 0 20px var(--safe-glow); }

        /* Container Cards Grid */
        .inventory-body {
            padding: 1.5rem 1.75rem;
            display: flex; flex-direction: column; gap: 1.15rem;
            overflow-y: auto; flex: 1;
        }

        .container-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.15rem;
            display: flex; flex-direction: column; gap: 0.85rem;
            transition: all 0.2s ease;
        }
        .container-card.compromised {
            border-color: var(--danger-red);
            box-shadow: 0 0 20px var(--danger-glow);
        }
        .container-card.healed {
            border-color: var(--safe-green);
            box-shadow: 0 0 15px var(--safe-glow);
        }

        .cntr-header { display: flex; justify-content: space-between; align-items: center; }
        .cntr-name { font-weight: 700; font-size: 0.95rem; color: var(--text-main); }
        .cntr-id { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--text-muted); }

        .status-badge {
            font-size: 0.7rem; font-weight: 700; padding: 0.25rem 0.75rem;
            border-radius: 20px; text-transform: uppercase; letter-spacing: 0.05em;
        }
        .status-badge.healthy { background: rgba(16, 185, 129, 0.1); color: var(--safe-green); border: 1px solid rgba(16, 185, 129, 0.3); }
        .status-badge.compromised { background: rgba(239, 68, 68, 0.1); color: var(--danger-red); border: 1px solid rgba(239, 68, 68, 0.3); animation: pulse-red 1.5s infinite; }
        .status-badge.healed { background: rgba(56, 189, 248, 0.1); color: var(--primary); border: 1px solid rgba(56, 189, 248, 0.3); }

        @keyframes pulse-red { 0% { opacity: 0.7; } 50% { opacity: 1; } 100% { opacity: 0.7; } }

        .metrics-row { display: flex; gap: 1.5rem; font-size: 0.78rem; color: var(--text-muted); }
        .metric-item { display: flex; flex-direction: column; gap: 0.15rem; }
        .metric-val { font-weight: 700; color: var(--text-main); font-size: 0.85rem; }

        .process-box {
            background: var(--terminal-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.65rem 0.85rem;
            font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #94a3b8;
            display: flex; flex-direction: column; gap: 0.25rem;
        }

        /* Right Panel Posture & Timeline */
        .posture-hero {
            padding: 1.75rem;
            border-bottom: 1px solid var(--border);
            background: var(--bg-surface);
            display: flex; justify-content: space-between; align-items: center;
        }
        .hero-title { font-size: 1.4rem; font-weight: 800; letter-spacing: -0.02em; }

        .timeline-body {
            padding: 1.75rem; overflow-y: auto; flex: 1;
            display: flex; flex-direction: column; gap: 1.25rem;
        }

        .step-card {
            background: var(--bg-card);
            border-left: 3px solid var(--primary);
            border-radius: 6px;
            padding: 0.85rem 1.15rem;
            font-size: 0.82rem; line-height: 1.55;
            display: flex; flex-direction: column; gap: 0.25rem;
            font-family: 'JetBrains Mono', monospace;
        }
        .step-stage { font-size: 0.68rem; font-weight: 700; color: var(--accent-amber); text-transform: uppercase; }

        /* Modal Overlay */
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(6px); display: none;
            align-items: center; justify-content: center; z-index: 1000;
        }
        .modal-box {
            background: var(--bg-surface);
            border: 1px solid var(--border); border-radius: 12px;
            width: 90%; max-width: 650px; max-height: 80vh;
            display: flex; flex-direction: column;
            box-shadow: 0 25px 50px rgba(0,0,0,0.5); overflow: hidden;
        }
        .modal-header {
            padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
            background: var(--bg-base);
        }
        .modal-body {
            padding: 1.75rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1.25rem;
        }
        .code-box {
            background: var(--terminal-bg); border: 1px solid var(--border);
            border-radius: 6px; padding: 1rem;
            font-family: 'JetBrains Mono', monospace; font-size: 0.78rem;
            white-space: pre-wrap; word-break: break-all; color: #e2e8f0;
        }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="logo-box">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <h1>Sentinel</h1>
        </div>
        <div class="engine-badge" id="engine-status-badge">
            <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--safe-green);"></span>
            <span id="engine-status-text">SENTINEL ENGINE ACTIVE</span>
        </div>
    </header>

    <main>
        <!-- Left Panel: Live Container Inventory & Attack Launchers -->
        <div class="column col-left">
            <div class="section-header">
                <span class="section-title">Active Container Workloads</span>
                <button class="btn-launch" onclick="launchTestContainer()">+ Launch Real Docker Container</button>
            </div>

            <div class="controls-bar">
                <span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">Inject Attack Payload:</span>
                <button class="sim-btn" onclick="triggerAttack('reverse_shell')">Reverse Shell</button>
                <button class="sim-btn" onclick="triggerAttack('cryptominer')">CryptoMiner</button>
                <button class="sim-btn" onclick="triggerAttack('file_tamper')">File Tamper</button>

                <button class="btn-heal" onclick="runSelfHealing()">⚡ Execute Self-Healing Protocol</button>
            </div>

            <div class="inventory-body" id="inventory-container">
                <!-- Live Container Cards -->
            </div>
        </div>

        <!-- Right Panel: Posture & Real-Time Remediation Timeline -->
        <div class="column col-right">
            <div class="section-header">
                <span class="section-title">Autonomous Remediation Log</span>
            </div>

            <div class="posture-hero">
                <div>
                    <div class="hero-title" id="posture-title" style="color:var(--safe-green);">SYSTEM PROTECTED</div>
                    <span style="font-size:0.75rem; color:var(--text-muted);">Real-Time Process & Network Isolation Engine Standing By</span>
                </div>
            </div>

            <div class="timeline-body">
                <div style="display:flex; flex-direction:column; gap:0.65rem;">
                    <span class="section-title">4-Stage Self-Healing Execution Trace</span>
                    <div id="timeline-container" style="display:flex; flex-direction:column; gap:0.75rem;">
                        <div class="step-card" style="color:var(--text-muted);">
                            No active threats detected. Autonomous self-healing daemon monitoring host container processes.
                        </div>
                    </div>
                </div>

                <div style="display:flex; flex-direction:column; gap:0.65rem; margin-top:1rem;">
                    <span class="section-title">AI Forensic Patch Generator</span>
                    <button class="sim-btn" style="width:100%; padding:0.75rem; border-radius:8px; font-weight:700;" onclick="openForensicsModal()">
                        🔍 Inspect AI Forensic Patch & Hardened Dockerfile
                    </button>
                </div>
            </div>
        </div>
    </main>

    <!-- Modal for AI Forensics -->
    <div class="modal-overlay" id="modal-overlay" onclick="closeModal(event)">
        <div class="modal-box" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h2 style="font-size:1.1rem; font-weight:700;">AI Security Patch & Forensic Diagnosis</h2>
                <button style="background:none; border:none; font-size:1.4rem; cursor:pointer; color:var(--text-muted);" onclick="closeModal()">×</button>
            </div>
            <div class="modal-body" id="modal-body">
                <p>Click "Execute Self-Healing Protocol" to generate AI forensic patch telemetry.</p>
            </div>
        </div>
    </div>

    <script>
        let currentContainers = [];

        async function fetchContainers() {
            try {
                const resp = await fetch('/api/containers');
                currentContainers = await resp.json();
                renderContainers(currentContainers);
            } catch (e) {
                console.error("Error fetching containers:", e);
            }
        }

        function renderContainers(containers) {
            const containerEl = document.getElementById('inventory-container');
            containerEl.innerHTML = '';

            let hasCompromised = false;

            containers.forEach(c => {
                let statusClass = 'healthy';
                let badgeLabel = c.health;

                if (c.health === 'COMPROMISED') {
                    statusClass = 'compromised';
                    hasCompromised = true;
                } else if (c.health.includes('SELF-HEALED')) {
                    statusClass = 'healed';
                }

                const card = document.createElement('div');
                card.className = `container-card ${statusClass}`;
                card.innerHTML = `
                    <div class="cntr-header">
                        <div>
                            <span class="cntr-name">${c.name}</span>
                            <span class="cntr-id"> (${c.container_id})</span>
                        </div>
                        <span class="status-badge ${statusClass}">${badgeLabel}</span>
                    </div>

                    <div class="metrics-row">
                        <div class="metric-item">
                            <span>Image</span>
                            <span class="metric-val">${c.image}</span>
                        </div>
                        <div class="metric-item">
                            <span>CPU Usage</span>
                            <span class="metric-val">${c.cpu_usage_pct}%</span>
                        </div>
                        <div class="metric-item">
                            <span>Memory</span>
                            <span class="metric-val">${c.memory_mb} MB</span>
                        </div>
                        <div class="metric-item">
                            <span>Network</span>
                            <span class="metric-val">${c.network_status}</span>
                        </div>
                    </div>

                    <div class="process-box">
                        <span style="font-weight:700; color:var(--primary);">ACTIVE PROCESS TREE:</span>
                        ${c.processes.map(p => `<div>> ${p}</div>`).join('')}
                    </div>
                `;
                containerEl.appendChild(card);
            });

            // Update Posture Status
            const pTitle = document.getElementById('posture-title');
            if (hasCompromised) {
                pTitle.innerText = 'CONTAINER BREACH DETECTED';
                pTitle.style.color = 'var(--danger-red)';
            } else {
                pTitle.innerText = 'SYSTEM PROTECTED';
                pTitle.style.color = 'var(--safe-green)';
            }
        }

        async function launchTestContainer() {
            const resp = await fetch('/api/launch-container', { method: 'POST' });
            const data = await resp.json();
            alert(data.message);
            await fetchContainers();
        }

        async function triggerAttack(attackType) {
            if (currentContainers.length === 0) return;
            const targetId = currentContainers[0].container_id;

            await fetch('/api/simulate-attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container_id: targetId, attack_type: attackType })
            });
            await fetchContainers();
        }

        async function runSelfHealing() {
            if (currentContainers.length === 0) return;
            const targetId = currentContainers[0].container_id;

            const resp = await fetch('/api/self-heal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container_id: targetId })
            });

            const record = await resp.json();
            renderTimeline(record);
            await fetchContainers();
        }

        function renderTimeline(record) {
            const containerEl = document.getElementById('timeline-container');
            containerEl.innerHTML = '';

            if (record.steps) {
                record.steps.forEach(st => {
                    const card = document.createElement('div');
                    card.className = 'step-card';
                    card.innerHTML = `
                        <div class="step-stage">Stage ${st.stage}: ${st.action} (${st.time || st.timestamp})</div>
                        <div>${st.details}</div>
                    `;
                    containerEl.appendChild(card);
                });
            }
        }

        async function openForensicsModal() {
            if (currentContainers.length === 0) return;
            const targetId = currentContainers[0].container_id;

            const resp = await fetch(`/api/forensics/${targetId}`);
            const patch = await resp.json();

            const body = document.getElementById('modal-body');
            body.innerHTML = `
                <p><strong>AI Security Engine:</strong> ${patch.ai_engine}</p>
                <p><strong>Forensic Root Cause Diagnosis:</strong></p>
                <div class="code-box">${patch.forensic_diagnosis}</div>

                <p><strong>Auto-Generated Hardened Dockerfile Patch:</strong></p>
                <div class="code-box">${patch.hardened_dockerfile}</div>

                <p><strong>Auto-Generated Hardened docker-compose.yml Policy:</strong></p>
                <div class="code-box">${patch.hardened_compose}</div>
            `;
            document.getElementById('modal-overlay').style.display = 'flex';
        }

        function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
        }

        fetchContainers();
        setInterval(fetchContainers, 3000);
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return DASHBOARD_HTML

@app.get("/api/containers")
async def get_containers():
    return docker_daemon.get_real_containers()

@app.post("/api/launch-container")
async def launch_container():
    return docker_daemon.launch_real_test_container()

@app.post("/api/simulate-attack")
async def simulate_attack(req: AttackModel):
    return docker_daemon.inject_real_attack(req.container_id, req.attack_type)

@app.post("/api/self-heal")
async def self_heal(req: HealModel):
    return docker_daemon.execute_real_self_healing(req.container_id)

@app.get("/api/forensics/{container_id}")
async def get_forensics(container_id: str):
    cntrs = docker_daemon.get_real_containers()
    target = next((c for c in cntrs if c["container_id"] == container_id or c["name"] == container_id), {})
    forensic_payload = {
        "container_id": container_id,
        "name": target.get("name", "container"),
        "process_tree_snapshot": target.get("processes", [])
    }
    return ai_forensics.generate_forensic_patch(forensic_payload)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8500)
