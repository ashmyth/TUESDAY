/* ==========================================================================
   TUESDAY: Digital SOC Twin Topology Canvas Renderer
   ========================================================================== */

class DigitalSOCTwin {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        
        this.nodes = [
            { id: 'FW-PERIMETER-01', name: 'Perimeter Palo Alto FW', type: 'Firewall', enclave: 'Network Gateway', x: 0.15, y: 0.5, status: 'healthy', ip: '203.0.113.1' },
            { id: 'DC-PRIMARY-01', name: 'Domain Controller AD', type: 'Domain Controller', enclave: 'Core Infrastructure', x: 0.45, y: 0.25, status: 'healthy', ip: '192.168.1.10' },
            { id: 'FIN-SERVER-04', name: 'FIN-SERVER-04 App', type: 'Workstation', enclave: 'Finance Subnet', x: 0.45, y: 0.65, status: 'healthy', ip: '192.168.10.45' },
            { id: 'DEV-WORKSTATION-09', name: 'DEV-WORKSTATION-09', type: 'Workstation', enclave: 'Developer Sandbox', x: 0.45, y: 0.85, status: 'healthy', ip: '192.168.20.14' },
            { id: 'DB-PROD-SQL-01', name: 'Production SQL DB', type: 'Database', enclave: 'Database Enclave', x: 0.75, y: 0.35, status: 'healthy', ip: '192.168.10.50' },
            { id: 'AWS-S3-PROD-LOGS', name: 'AWS S3 Cloud Vault', type: 'Cloud Resource', enclave: 'AWS us-east-1', x: 0.75, y: 0.75, status: 'healthy', ip: '10.0.4.12' }
        ];

        this.connections = [
            { from: 'FW-PERIMETER-01', to: 'DC-PRIMARY-01', active: false },
            { from: 'FW-PERIMETER-01', to: 'FIN-SERVER-04', active: false },
            { from: 'FW-PERIMETER-01', to: 'DEV-WORKSTATION-09', active: false },
            { from: 'FIN-SERVER-04', to: 'DC-PRIMARY-01', active: false },
            { from: 'FIN-SERVER-04', to: 'DB-PROD-SQL-01', active: false },
            { from: 'DC-PRIMARY-01', to: 'AWS-S3-PROD-LOGS', active: false }
        ];

        this.animFrame = null;
        this.selectedNode = null;

        this.initCanvas();
        this.startAnimation();
        this.bindEvents();
    }

    initCanvas() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
    }

    startAnimation() {
        let tick = 0;
        const render = () => {
            tick += 0.05;
            this.draw(tick);
            this.animFrame = requestAnimationFrame(render);
        };
        render();
    }

    draw(tick) {
        const w = this.canvas.width;
        const h = this.canvas.height;

        this.ctx.clearRect(0, 0, w, h);

        // Draw Grid Background
        this.ctx.strokeStyle = 'rgba(62, 122, 132, 0.10)';
        this.ctx.lineWidth = 1;
        const gridSize = 40;
        for (let x = 0; x < w; x += gridSize) {
            this.ctx.beginPath();
            this.ctx.moveTo(x, 0);
            this.ctx.lineTo(x, h);
            this.ctx.stroke();
        }
        for (let y = 0; y < h; y += gridSize) {
            this.ctx.beginPath();
            this.ctx.moveTo(0, y);
            this.ctx.lineTo(w, y);
            this.ctx.stroke();
        }

        // Draw connections
        this.connections.forEach(conn => {
            const n1 = this.nodes.find(n => n.id === conn.from);
            const n2 = this.nodes.find(n => n.id === conn.to);
            if (!n1 || !n2) return;

            const x1 = n1.x * w;
            const y1 = n1.y * h;
            const x2 = n2.x * w;
            const y2 = n2.y * h;

            this.ctx.beginPath();
            this.ctx.moveTo(x1, y1);
            this.ctx.lineTo(x2, y2);

            if (conn.active) {
                this.ctx.strokeStyle = '#FD4040';
                this.ctx.lineWidth = 2.5;
                this.ctx.shadowColor = '#FD4040';
                this.ctx.shadowBlur = 8;
            } else {
                this.ctx.strokeStyle = 'rgba(62, 122, 132, 0.28)';
                this.ctx.lineWidth = 1.5;
                this.ctx.shadowBlur = 0;
            }
            this.ctx.stroke();
            this.ctx.shadowBlur = 0;

            if (conn.active) {
                const progress = (Math.sin(tick * 3) + 1) / 2;
                const px = x1 + (x2 - x1) * progress;
                const py = y1 + (y2 - y1) * progress;

                this.ctx.beginPath();
                this.ctx.arc(px, py, 5, 0, Math.PI * 2);
                this.ctx.fillStyle = '#EEA4A5';
                this.ctx.fill();
            }
        });

        // Draw Nodes
        this.nodes.forEach(node => {
            const nx = node.x * w;
            const ny = node.y * h;

            let color = '#3E7A84'; // healthy palette teal
            if (node.status === 'suspicious') color = '#C97A7C';
            if (node.status === 'compromised') color = '#FD4040';
            if (node.status === 'isolated') color = '#4A8CA8';

            this.ctx.beginPath();
            this.ctx.arc(nx, ny, 24, 0, Math.PI * 2);
            this.ctx.fillStyle = color + '22';
            this.ctx.fill();
            this.ctx.strokeStyle = color;
            this.ctx.lineWidth = 2;
            this.ctx.stroke();

            if (node.status === 'compromised') {
                const pulseRadius = 24 + Math.sin(tick * 4) * 6;
                this.ctx.beginPath();
                this.ctx.arc(nx, ny, pulseRadius, 0, Math.PI * 2);
                this.ctx.strokeStyle = 'rgba(253, 64, 64, 0.45)';
                this.ctx.stroke();
            }

            // Node core
            this.ctx.beginPath();
            this.ctx.arc(nx, ny, 16, 0, Math.PI * 2);
            this.ctx.fillStyle = '#ffffff';
            this.ctx.fill();
            this.ctx.strokeStyle = color;
            this.ctx.stroke();

            // Label text
            this.ctx.fillStyle = '#1F2A2E';
            this.ctx.font = '700 11px "Share Tech Mono"';
            this.ctx.textAlign = 'center';
            this.ctx.fillText(node.name, nx, ny + 38);

            this.ctx.fillStyle = '#7C8DB0';
            this.ctx.font = '10px "Share Tech Mono"';
            this.ctx.fillText(node.ip, nx, ny + 50);
        });
    }

    setNodeStatus(nodeId, status) {
        const node = this.nodes.find(n => n.id === nodeId);
        if (node) node.status = status;
    }

    setAttackPath(fromId, toId) {
        let conn = this.connections.find(c => (c.from === fromId && c.to === toId) || (c.from === toId && c.to === fromId));
        if (!conn) {
            conn = { from: fromId, to: toId, active: true };
            this.connections.push(conn);
        } else {
            conn.active = true;
        }
    }

    injectThreatNode(ioc, targetHost) {
        if (!ioc) return;
        const cleanIoc = ioc.split(' ')[0].split(':')[0];
        const threatId = `EXT-${cleanIoc}`;
        let threatNode = this.nodes.find(n => n.id === threatId);

        if (!threatNode) {
            threatNode = {
                id: threatId,
                name: `Adversary C2 (${cleanIoc})`,
                type: 'External Adversary C2',
                enclave: 'Untrusted WAN',
                x: 0.12,
                y: 0.18,
                status: 'compromised',
                ip: cleanIoc,
                isExternal: true
            };
            this.nodes.push(threatNode);
        } else {
            threatNode.status = 'compromised';
        }

        // Map target host to internal node id
        let targetId = 'FIN-SERVER-04';
        if (targetHost) {
            if (targetHost.includes('DEV-WORKSTATION') || targetHost.includes('192.168.20')) targetId = 'DEV-WORKSTATION-09';
            else if (targetHost.includes('DC-PRIMARY') || targetHost.includes('192.168.1')) targetId = 'DC-PRIMARY-01';
            else if (targetHost.includes('DB-PROD') || targetHost.includes('192.168.10.50')) targetId = 'DB-PROD-SQL-01';
            else if (targetHost.includes('AWS') || targetHost.includes('S3')) targetId = 'AWS-S3-PROD-LOGS';
        }

        this.setNodeStatus(targetId, 'compromised');
        this.setAttackPath(threatId, 'FW-PERIMETER-01');
        this.setAttackPath('FW-PERIMETER-01', targetId);
    }

    containThreatNode(ioc, targetHost) {
        const cleanIoc = (ioc || '').split(' ')[0].split(':')[0];
        const threatId = `EXT-${cleanIoc}`;
        const threatNode = this.nodes.find(n => n.id === threatId);
        if (threatNode) threatNode.status = 'isolated';

        let targetId = 'FIN-SERVER-04';
        if (targetHost) {
            if (targetHost.includes('DEV-WORKSTATION') || targetHost.includes('192.168.20')) targetId = 'DEV-WORKSTATION-09';
            else if (targetHost.includes('DC-PRIMARY')) targetId = 'DC-PRIMARY-01';
        }
        this.setNodeStatus(targetId, 'isolated');

        // Deactivate active attack lines
        this.connections.forEach(c => {
            if (c.from === threatId || c.to === threatId) c.active = false;
        });
    }

    syncLiveTelemetry(telemetry) {
        if (!telemetry || !telemetry.sockets) return;
        const knownSuspicious = ['185.', '193.', '45.', '91.'];
        const socks = telemetry.sockets.sockets || [];
        socks.forEach(s => {
            if (s.isExternal && knownSuspicious.some(p => s.remote.startsWith(p))) {
                const extIp = s.remote.split(':')[0];
                this.injectThreatNode(extIp, 'FIN-SERVER-04');
            }
        });
    }

    resetTopology() {
        this.nodes = this.nodes.filter(n => !n.isExternal);
        this.nodes.forEach(n => n.status = 'healthy');
        this.connections.forEach(c => c.active = false);
    }

    bindEvents() {
        window.addEventListener('resize', () => this.initCanvas());

        this.canvas.addEventListener('click', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            const w = this.canvas.width;
            const h = this.canvas.height;

            const clicked = this.nodes.find(n => {
                const nx = n.x * w;
                const ny = n.y * h;
                return Math.hypot(mouseX - nx, mouseY - ny) <= 25;
            });

            if (clicked) {
                this.selectedNode = clicked;
                this.showNodeInfo(clicked);
            }
        });
    }

    showNodeInfo(node) {
        const nameEl = document.getElementById('twin-info-name');
        const typeEl = document.getElementById('twin-info-type');
        const bodyEl = document.getElementById('twin-info-body');

        if (!nameEl || !bodyEl) return;

        nameEl.innerText = `${node.name} (${node.ip})`;
        typeEl.innerText = node.enclave;

        bodyEl.innerHTML = `
            <p><strong>STATUS:</strong> <span class="badge badge-matrix-${node.status === 'compromised' ? 'red' : node.status === 'isolated' ? 'cyan' : 'green'}">${node.status.toUpperCase()}</span></p>
            <p><strong>ASSET TYPE:</strong> ${node.type}</p>
            <p><strong>ENCLAVE:</strong> ${node.enclave}</p>
            <p><strong>EDR AGENT:</strong> Active (v4.18.2)</p>
            <p><strong>LAST TELEMETRY:</strong> ${new Date().toLocaleTimeString()}</p>
        `;
    }
}
