/* ==========================================================================
   TUESDAY: Multi-Tier Agent Memory System
   Episodic Memory | Semantic Threat Memory | IOC Cache | Knowledge Base
   ========================================================================== */

class SOCMemorySystem {
    constructor() {
        // 1. Episodic Memory Store (Past Incidents)
        this.episodicMemory = [
            {
                id: 'MEM-EP-2026-001',
                timestamp: '2026-08-01T10:14:00Z',
                title: 'LockBit 2.0 Ransomware Containment',
                enclave: 'Finance Subnet',
                rootCause: 'Spearphishing macro attachment executed on FIN-WS-02',
                actionsTaken: [
                    'Host isolated via CrowdStrike API',
                    'Firewall rule added for IP 185.220.101.5',
                    'Domain credentials reset for user jsmith'
                ],
                resolutionOutcome: 'SUCCESS - Zero file encryption propagated',
                mttrSeconds: 4.2
            },
            {
                id: 'MEM-EP-2026-002',
                timestamp: '2026-08-04T14:22:00Z',
                title: 'AWS S3 Bucket Unauthorized Access',
                enclave: 'AWS Production Cloud',
                rootCause: 'Leaked IAM access key AKIAIOSFODNN7EXAMPLE in public GitHub repository',
                actionsTaken: [
                    'Revoked IAM key via AWS IAM API',
                    'Applied deny policy on S3 bucket telemetry-logs-prod',
                    'Enabled CloudTrail S3 Data Event Audit'
                ],
                resolutionOutcome: 'SUCCESS - Revoked active STS tokens within 46s',
                mttrSeconds: 46
            }
        ];

        // 2. Semantic Memory (Threat & Asset Graph)
        this.semanticMemory = {
            threatActors: [
                { name: 'APT29 (Cozy Bear)', origin: 'State-Sponsored', primaryTTPs: ['T1566.002', 'T1059.001', 'T1071.001'], targetSectors: ['Government', 'Defense', 'Finance'] },
                { name: 'LockBit Gang', origin: 'Cybercrime Syndicate', primaryTTPs: ['T1486', 'T1003.001', 'T1490'], targetSectors: ['Enterprise', 'Healthcare', 'Critical Infrastructure'] }
            ],
            assetRegistry: [
                { id: 'DC-PRIMARY-01', ip: '192.168.1.10', type: 'Domain Controller', criticality: 'CRITICAL', enclave: 'Core Infrastructure' },
                { id: 'DB-PROD-SQL-01', ip: '192.168.10.50', type: 'Database Server', criticality: 'CRITICAL', enclave: 'Database Subnet' },
                { id: 'FIN-SERVER-04', ip: '192.168.10.45', type: 'Workstation / App Server', criticality: 'HIGH', enclave: 'Finance Enclave' },
                { id: 'AWS-S3-PROD-LOGS', ip: 'cloud-aws', type: 'Cloud S3 Storage', criticality: 'HIGH', enclave: 'AWS us-east-1' }
            ]
        };

        // 3. IOC Threat Intelligence Cache
        this.iocCache = new Map();

        // 4. Organizational Knowledge Base & SLA Policies
        this.knowledgeBase = {
            slaPolicies: {
                criticalMTTR: 300, // 5 mins max
                highMTTR: 900,
                autoApprovalThreshold: 80 // Risk score out of 100
            },
            playbooks: [
                {
                    id: 'PLAYBOOK-RANSOMWARE',
                    name: 'Automated Ransomware Emergency Isolation',
                    steps: [
                        'Step 1: Isolate host network adapter (CrowdStrike / EDR)',
                        'Step 2: Terminate malicious process PID & parent powershell.exe',
                        'Step 3: Block external C2 IP on Perimeter Palo Alto Firewall',
                        'Step 4: Block compromised Active Directory account',
                        'Step 5: Trigger Volume Shadow Copy restoration dry-run'
                    ]
                },
                {
                    id: 'PLAYBOOK-CLOUD-EXFIL',
                    name: 'AWS Cloud Credential Compromise Containment',
                    steps: [
                        'Step 1: Immediately detach all IAM policies from compromised User/Role',
                        'Step 2: Attach Explicit AWS DenyAll inline policy',
                        'Step 3: Invalidate active STS session tokens',
                        'Step 4: Audit CloudTrail logs for S3 GetObject access in last 24h'
                    ]
                }
            ]
        };
    }

    // Add new incident to Episodic Memory
    addEpisodicMemory(incident) {
        incident.id = `MEM-EP-${new Date().getFullYear()}-${Math.floor(100 + Math.random() * 900)}`;
        this.episodicMemory.unshift(incident);
        if (this.episodicMemory.length > 20) this.episodicMemory.pop();
    }

    // Query similar past incidents from Episodic Memory
    querySimilarIncidents(threatType) {
        return this.episodicMemory.filter(item => 
            item.title.toLowerCase().includes(threatType.toLowerCase()) ||
            item.rootCause.toLowerCase().includes(threatType.toLowerCase())
        );
    }

    // Cache IOC lookup result
    cacheIoc(ioc, data) {
        this.iocCache.set(ioc, {
            data: data,
            cachedAt: new Date()
        });
    }

    getIocCache(ioc) {
        return this.iocCache.get(ioc);
    }
}

const SOCMemory = new SOCMemorySystem();
