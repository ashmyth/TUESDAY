/* ==========================================================================
   TUESDAY: MITRE ATT&CK Matrix & TTP Detail Modal Engine
   ========================================================================== */

const MitreEngine = {
    tactics: [
        {
            name: "Initial Access",
            techniques: [
                { id: "T1566", name: "Phishing", desc: "Spearphishing links/attachments targeting employees." },
                { id: "T1190", name: "Exploit Public App", desc: "Web server zero-day exploit execution." },
                { id: "T1078", name: "Valid Accounts", desc: "Compromised cloud IAM credentials." }
            ]
        },
        {
            name: "Execution",
            techniques: [
                { id: "T1059", name: "Command Interpreter", desc: "PowerShell / CMD encoded command execution." },
                { id: "T1204", name: "User Execution", desc: "Malicious payload launched by user." },
                { id: "T1047", name: "WMI Execution", desc: "Windows Management Instrumentation execution." }
            ]
        },
        {
            name: "Persistence",
            techniques: [
                { id: "T1547", name: "Boot Autostart", desc: "Registry run keys / startup folder persistence." },
                { id: "T1053", name: "Scheduled Task", desc: "Task Scheduler persistence payload." }
            ]
        },
        {
            name: "Defense Evasion",
            techniques: [
                { id: "T1027", name: "Obfuscated Files", desc: "Base64 payload encoding / binary packer." },
                { id: "T1562", name: "Impair Defenses", desc: "Disabling EDR agent / Antivirus services." },
                { id: "T1490", name: "Inhibit Recovery", desc: "vssadmin shadow copy deletion." }
            ]
        },
        {
            name: "Credential Access",
            techniques: [
                { id: "T1003", name: "OS Credential Dumping", desc: "LSASS process memory reading via Mimikatz." },
                { id: "T1110", name: "Brute Force", desc: "Password spraying against Entra ID." }
            ]
        },
        {
            name: "Lateral Movement",
            techniques: [
                { id: "T1021", name: "Remote Services", desc: "SMB / WinRM / PsExec lateral jump." },
                { id: "T1570", name: "Tool Transfer", desc: "Staging Cobalt Strike beacon DLLs." }
            ]
        },
        {
            name: "Impact / Exfil",
            techniques: [
                { id: "T1486", name: "Data Encrypted", desc: "Ransomware AES/RSA file encryption." },
                { id: "T1567", name: "Exfil to Web Service", desc: "S3 KMS data download & external POST." }
            ]
        }
    ],

    detectedTTPs: new Set(),

    renderMatrix(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        let html = '';
        this.tactics.forEach(tactic => {
            html += `<div class="mitre-column">
                <div class="mitre-header">${tactic.name}</div>`;
            
            tactic.techniques.forEach(tech => {
                const isDetected = this.detectedTTPs.has(tech.id);
                html += `
                    <div class="mitre-card ${isDetected ? 'detected' : ''}" data-ttp="${tech.id}">
                        <div class="ttp-id">${tech.id}</div>
                        <div class="ttp-name">${tech.name}</div>
                    </div>
                `;
            });

            html += `</div>`;
        });

        container.innerHTML = html;

        // Bind clicks to open TTP Detail Modal
        container.querySelectorAll('.mitre-card').forEach(card => {
            card.addEventListener('click', () => {
                const ttpId = card.getAttribute('data-ttp');
                this.showTTPDetailModal(ttpId);
            });
        });

        const badge = document.getElementById('mitre-active-ttp-count');
        if (badge) {
            badge.innerText = `${this.detectedTTPs.size} Active TTPs`;
        }
    },

    flagTTP(ttpId) {
        this.detectedTTPs.add(ttpId);
        this.renderMatrix('mitre-matrix-container');
    },

    clearTTPs() {
        this.detectedTTPs.clear();
        this.renderMatrix('mitre-matrix-container');
    },

    showTTPDetailModal(ttpId) {
        let foundTech = null;
        let foundTactic = '';

        for (const tactic of this.tactics) {
            for (const tech of tactic.techniques) {
                if (tech.id === ttpId) {
                    foundTech = tech;
                    foundTactic = tactic.name;
                    break;
                }
            }
        }

        if (!foundTech) return;

        const isDetected = this.detectedTTPs.has(ttpId);

        const modal = document.getElementById('modal-report');
        const body = document.getElementById('report-modal-body');
        if (!modal || !body) return;

        body.innerHTML = `
            <div style="font-family:var(--font-mono); color:var(--text-main); line-height:1.6;">
                <div style="display:flex; justify-between; align-items:center; border-bottom:2px solid var(--matrix-green); padding-bottom:0.5rem; margin-bottom:1rem;">
                    <div>
                        <h2 style="color:var(--matrix-green); font-size:1.3rem;">[${foundTech.id}] ${foundTech.name}</h2>
                        <div style="font-size:0.78rem; color:var(--text-muted);">Tactic Stage: <strong>${foundTactic}</strong></div>
                    </div>
                    <div>
                        <span class="badge badge-matrix-${isDetected ? 'red' : 'green'}">${isDetected ? 'DETECTED IN ACTIVE INCIDENT' : 'MONITORING'}</span>
                    </div>
                </div>

                <h3>Description</h3>
                <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:1rem;">${foundTech.desc}</p>

                <h3>Detection Logic & Sigma Rule</h3>
                <div style="background:rgba(62,122,132,0.10); border:1px solid var(--matrix-card-border); padding:0.8rem; border-radius:4px; font-size:0.75rem; margin-bottom:1rem;">
                    <code style="color:var(--text-main);">sigma_rule: SIGMA-2026-${foundTech.id.replace('T', '')}<br>
                    pattern: "${foundTech.name.toLowerCase()}" OR "${foundTech.id}"<br>
                    action: ALERT_SWARM & DISPATCH_LOG_ANALYSIS_AGENT</code>
                </div>

                <h3>Recommended Remediation & Playbook Action</h3>
                <ul style="font-size:0.8rem; color:var(--text-muted); margin-left:1.5rem;">
                    <li>Execute EDR network interface isolation on target endpoint.</li>
                    <li>Block malicious C2 proxy IP on perimeter Palo Alto Firewall.</li>
                    <li>Revoke domain user credentials and invalidate active STS sessions.</li>
                </ul>
            </div>
        `;

        modal.classList.add('active');
    }
};
