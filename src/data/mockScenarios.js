// =============================================================
// INTROSPECT AI — Three fully independent scenario datasets
// Each scenario has unique: hosts, detections, graph topology,
// network logs, SHAP values, infiltration timeline, narrative,
// MITRE stages, and overview stats.
// =============================================================

// ─────────────────────────────────────────────────────────────
// SCENARIO A: CIC-IDS-2018 — SSH Brute Force & Lateral Movement
// ─────────────────────────────────────────────────────────────
const scenarioA = {
  name: 'Scenario A: External Brute Force & Lateral Movement',

  overviewStats: {
    totalFlows: 14893,
    maliciousFlows: 2847,
    activeAlerts: 4,
    dataset: 'CIC-IDS-2018',
    subset: 'Thursday-WorkingHours (SSH-Bruteforce)',
    rows: '14,893 flows',
    features: 78,
    duration: '15 min window',
    attackTypes: ['SSH-Bruteforce', 'Infiltration'],
    worldModelConfidence: 82,
    worldModelTrend: 'Rising — predicted to reach 94% in 3 windows',
    infiltrationProbability: 0.82,
  },

  hosts: {
    attacker: {
      id: 'attacker-1',
      ip: '10.254.50.107',
      hostname: 'VMAL #1',
      os: 'Windows Server 2016',
      sensor: 'Sensor stack 00',
      privilege: '1 - Low',
      lastSeen: '2025-08-29T17:29:00Z',
      roles: ['File Server'],
      entityImportance: 'Medium',
      attackRating: 10,
      velocity: 'High',
      urgencyScore: 100,
      priorityStatus: 'Prioritized',
    },
    targets: [
      { id: 't1', ip: '192.168.1.10', hostname: 'WEB-SVR-01', os: 'Linux', role: 'Web Server' },
      { id: 't2', ip: '192.168.1.11', hostname: 'WEB-SVR-02', os: 'Linux', role: 'Web Server' },
      { id: 't3', ip: '192.168.1.12', hostname: 'APP-SVR-01', os: 'Windows', role: 'App Server' },
      { id: 't4', ip: '192.168.1.15', hostname: 'DB-SVR-01', os: 'Linux', role: 'Database' },
      { id: 't5', ip: '192.168.1.20', hostname: 'FILE-SVR-01', os: 'Windows', role: 'File Server' },
      { id: 't6', ip: '192.168.1.25', hostname: 'DC-01', os: 'Windows', role: 'Domain Controller' },
    ],
  },

  attackProfile: {
    classification: 'External Adversary',
    description: 'Active behaviors associated with sophisticated, objective-oriented adversary targeting SSH services.',
    positiveIndicators: ['Data Smuggler', 'File Share Enumeration', 'Port Scan', 'RDP Recon', 'RPC Recon', 'Hidden HTTP Tunnel', 'SMB Account Scan'],
  },

  mitreStages: [
    { id: 'RECON', name: 'Reconnaissance', icon: '🔍', status: 'confirmed', desc: 'Port scanning detected', prob: null },
    { id: 'INIT', name: 'Initial Access', icon: '🚪', status: 'confirmed', desc: 'SSH brute force (850 SYN)', prob: null },
    { id: 'CRED', name: 'Credential Access', icon: '🔑', status: 'confirmed', desc: 'Auth success after 47 fails', prob: null },
    { id: 'LATERAL', name: 'Lateral Movement', icon: '⚡', status: 'current', desc: 'SMB to FILE-SVR-01', prob: '82%' },
    { id: 'C2', name: 'Command & Control', icon: '📡', status: 'predicted', desc: 'HTTP tunnel predicted', prob: '87%' },
    { id: 'EXFIL', name: 'Exfiltration', icon: '📤', status: 'predicted', desc: 'Data staging likely', prob: '91%' },
    { id: 'IMPACT', name: 'Impact', icon: '💥', status: 'inactive', desc: 'Not yet predicted', prob: null },
  ],

  urgencyTimeline: [
    { time: 'Sep 12', value: 0 },
    { time: 'Sep 12 19:00', value: 0 },
    { time: 'Sep 13', value: 0 },
    { time: 'Sep 13 19:00', value: 0 },
    { time: 'Sep 14', value: 0 },
    { time: 'Sep 14 19:00', value: 5 },
    { time: 'Sep 15', value: 10 },
    { time: 'Sep 15 19:00', value: 15 },
    { time: 'Sep 16 04:04', value: 100 },
    { time: 'Sep 16 19:00', value: 100 },
    { time: 'Sep 17', value: 100 },
    { time: 'Sep 17 19:00', value: 100 },
    { time: 'Sep 18', value: 100 },
  ],

  detections: [
    { id: 'd1', category: 'Info', categoryClass: 'info', type: 'New Host Role Detected', status: 'Active', statusClass: 'active', firstSeen: '2025-08-29T17:29:00Z', lastSeen: '2025-08-29T17:29:00Z' },
    { id: 'd2', category: 'C&C', categoryClass: 'cc', type: 'Hidden HTTP Tunnel', status: 'Inactive', statusClass: 'inactive', firstSeen: '2025-08-15T15:43:00Z', lastSeen: '2025-08-28T12:50:00Z' },
    { id: 'd3', category: 'C&C', categoryClass: 'cc', type: 'Suspect HTTP Activity: PowerShell Empire', status: 'Inactive', statusClass: 'inactive', firstSeen: '2025-08-15T15:43:00Z', lastSeen: '2025-08-28T12:49:00Z' },
    { id: 'd4', category: 'C&C', categoryClass: 'cc', type: 'Hidden HTTPS Tunnel', status: 'Inactive', statusClass: 'inactive', firstSeen: '2025-08-15T15:46:00Z', lastSeen: '2025-08-28T11:57:00Z' },
    { id: 'd5', category: 'Recon', categoryClass: 'recon', type: 'SMB Account Scan', status: 'Fixed', statusClass: 'fixed', firstSeen: '2025-08-22T13:48:00Z', lastSeen: '2025-08-25T21:27:00Z' },
    { id: 'd6', category: 'Recon', categoryClass: 'recon', type: 'Expected Activity For 50-107 (SMB Account Scan)', status: 'Filtered', statusClass: 'filtered', firstSeen: '2025-08-22T13:48:00Z', lastSeen: '2025-08-25T21:27:00Z' },
    { id: 'd7', category: 'Lateral', categoryClass: 'lateral', type: 'File Share Enumeration', status: 'Active', statusClass: 'active', firstSeen: '2025-08-22T06:45:00Z', lastSeen: '2025-09-02T17:48:00Z' },
    { id: 'd8', category: 'Lateral', categoryClass: 'lateral', type: 'RPC Targeted Recon', status: 'Active', statusClass: 'active', firstSeen: '2025-08-22T06:51:00Z', lastSeen: '2025-09-02T17:45:00Z' },
  ],

  infiltrationTimeline: [
    { window: 't-10', time: '14:00', probability: 0.05, tactic: 'Benign', type: 'real' },
    { window: 't-9', time: '14:01', probability: 0.08, tactic: 'Benign', type: 'real' },
    { window: 't-8', time: '14:02', probability: 0.12, tactic: 'Recon', type: 'real' },
    { window: 't-7', time: '14:03', probability: 0.22, tactic: 'Recon', type: 'real' },
    { window: 't-6', time: '14:04', probability: 0.35, tactic: 'Initial Access', type: 'real' },
    { window: 't-5', time: '14:05', probability: 0.48, tactic: 'Credential Access', type: 'real' },
    { window: 't-4', time: '14:06', probability: 0.55, tactic: 'Credential Access', type: 'real' },
    { window: 't-3', time: '14:07', probability: 0.62, tactic: 'Credential Access', type: 'real' },
    { window: 't-2', time: '14:08', probability: 0.71, tactic: 'Lateral Movement', type: 'real' },
    { window: 't-1', time: '14:09', probability: 0.78, tactic: 'Lateral Movement', type: 'real' },
    { window: 'NOW', time: '14:10', probability: 0.82, tactic: 'Lateral Movement', type: 'real' },
    { window: 't+1', time: '14:11', probability: 0.87, tactic: 'C2', type: 'predicted' },
    { window: 't+2', time: '14:12', probability: 0.91, tactic: 'Exfiltration', type: 'predicted' },
    { window: 't+3', time: '14:13', probability: 0.94, tactic: 'Exfiltration', type: 'predicted' },
  ],

  shapValues: [
    { feature: 'SYN flag ratio', value: 0.34, direction: 'positive' },
    { feature: 'Lateral SMB conn.', value: 0.28, direction: 'positive' },
    { feature: 'Attack tempo', value: 0.19, direction: 'positive' },
    { feature: 'Port 22 focus', value: 0.15, direction: 'positive' },
    { feature: 'Flow duration', value: 0.09, direction: 'positive' },
    { feature: 'Unique dst ports', value: 0.07, direction: 'positive' },
    { feature: 'Packet size var.', value: -0.04, direction: 'negative' },
  ],

  explainabilityMeta: {
    calibratedProbability: '91%',
    confidenceLevel: 'HIGH',
    evidenceMatch: '3/3 Correlation',
  },

  networkLogs: [
    { id: 1, ts: '14:00:01.234', src: '10.254.50.107', dst: '192.168.1.10', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'Benign', severity: 'low' },
    { id: 2, ts: '14:00:01.567', src: '10.254.50.107', dst: '192.168.1.11', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'Benign', severity: 'low' },
    { id: 3, ts: '14:00:02.102', src: '192.168.1.10', dst: '10.254.50.107', proto: 'TCP', port: 22, flags: 'SYN-ACK', bytes: 74, label: 'Benign', severity: 'low' },
    { id: 4, ts: '14:00:02.891', src: '10.254.50.107', dst: '192.168.1.12', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'Benign', severity: 'low' },
    { id: 5, ts: '14:01:15.443', src: '10.254.50.107', dst: '192.168.1.10', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'SSH-Bruteforce', severity: 'critical' },
    { id: 6, ts: '14:01:15.890', src: '10.254.50.107', dst: '192.168.1.10', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'SSH-Bruteforce', severity: 'critical' },
    { id: 7, ts: '14:01:16.221', src: '10.254.50.107', dst: '192.168.1.11', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'SSH-Bruteforce', severity: 'critical' },
    { id: 8, ts: '14:01:16.553', src: '10.254.50.107', dst: '192.168.1.12', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'SSH-Bruteforce', severity: 'critical' },
    { id: 9, ts: '14:01:17.010', src: '10.254.50.107', dst: '192.168.1.15', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'SSH-Bruteforce', severity: 'critical' },
    { id: 10, ts: '14:02:05.332', src: '10.254.50.107', dst: '192.168.1.12', proto: 'TCP', port: 22, flags: 'ACK', bytes: 1240, label: 'SSH-Bruteforce', severity: 'high' },
    { id: 11, ts: '14:02:10.112', src: '192.168.1.12', dst: '10.254.50.107', proto: 'TCP', port: 22, flags: 'PSH-ACK', bytes: 3400, label: 'SSH-Bruteforce', severity: 'high' },
    { id: 12, ts: '14:02:45.881', src: '10.254.50.107', dst: '192.168.1.25', proto: 'TCP', port: 445, flags: 'SYN', bytes: 74, label: 'Infiltration', severity: 'critical' },
    { id: 13, ts: '14:03:01.200', src: '192.168.1.12', dst: '192.168.1.20', proto: 'TCP', port: 445, flags: 'SYN', bytes: 74, label: 'Infiltration', severity: 'critical' },
    { id: 14, ts: '14:03:02.100', src: '192.168.1.20', dst: '192.168.1.12', proto: 'TCP', port: 445, flags: 'SYN-ACK', bytes: 74, label: 'Infiltration', severity: 'high' },
    { id: 15, ts: '14:03:15.445', src: '192.168.1.12', dst: '192.168.1.20', proto: 'TCP', port: 445, flags: 'PSH-ACK', bytes: 8920, label: 'Infiltration', severity: 'critical' },
    { id: 16, ts: '14:03:30.670', src: '192.168.1.12', dst: '192.168.1.25', proto: 'TCP', port: 135, flags: 'SYN', bytes: 74, label: 'Infiltration', severity: 'high' },
    { id: 17, ts: '14:03:45.321', src: '192.168.1.25', dst: '192.168.1.12', proto: 'TCP', port: 135, flags: 'SYN-ACK', bytes: 74, label: 'Benign', severity: 'low' },
    { id: 18, ts: '14:04:01.558', src: '10.254.50.107', dst: '192.168.1.30', proto: 'TCP', port: 25, flags: 'SYN', bytes: 74, label: 'Benign', severity: 'low' },
    { id: 19, ts: '14:04:15.889', src: '192.168.1.12', dst: '192.168.1.35', proto: 'TCP', port: 8080, flags: 'SYN', bytes: 74, label: 'Infiltration', severity: 'medium' },
    { id: 20, ts: '14:04:30.112', src: '192.168.1.12', dst: '10.254.20.107', proto: 'TCP', port: 443, flags: 'PSH-ACK', bytes: 15600, label: 'Exfiltration', severity: 'critical' },
    { id: 21, ts: '14:04:45.001', src: '10.254.20.107', dst: '192.168.1.12', proto: 'TCP', port: 443, flags: 'ACK', bytes: 54, label: 'Exfiltration', severity: 'high' },
    { id: 22, ts: '14:05:01.334', src: '192.168.1.12', dst: '10.254.20.107', proto: 'TCP', port: 443, flags: 'PSH-ACK', bytes: 32100, label: 'Exfiltration', severity: 'critical' },
    { id: 23, ts: '14:05:15.221', src: '192.168.1.20', dst: '192.168.1.12', proto: 'TCP', port: 445, flags: 'FIN-ACK', bytes: 54, label: 'Benign', severity: 'low' },
    { id: 24, ts: '14:05:30.009', src: '10.254.50.107', dst: '192.168.1.10', proto: 'ICMP', port: 0, flags: 'Echo', bytes: 98, label: 'Benign', severity: 'low' },
    { id: 25, ts: '14:05:45.778', src: '192.168.1.12', dst: '10.254.20.107', proto: 'UDP', port: 53, flags: 'Query', bytes: 256, label: 'Exfiltration', severity: 'high' },
  ],

  narrativeEntries: [
    { type: 'confirmed', timestamp: '14:02:15', text: 'Host 10.254.50.107 initiated a high-volume SSH brute force attack targeting 192.168.1.0/24. 850 SYN packets to port 22 across 15 destinations in 60 seconds.', evidence: 'Flow record — 850 SYN packets to port 22 across 15 destinations [Log: flow_id_8834]' },
    { type: 'confirmed', timestamp: '14:03:10', text: 'Attacker successfully authenticated to 192.168.1.12 (APP-SVR-01) via SSH after 47 failed attempts.', evidence: 'Windows Event 4624 — Successful logon, user "admin", source 10.254.50.107 [Log: evt_id_12847]' },
    { type: 'confirmed', timestamp: '14:03:25', text: 'Compromised host 192.168.1.12 initiated SMB connection to 192.168.1.20 (FILE-SVR-01) — lateral movement detected.', evidence: 'Flow record — 192.168.1.12:49512 → 192.168.1.20:445 [Log: flow_id_9021]' },
    { type: 'predicted', timestamp: '+2 min', text: 'World Model forecasts with 87% confidence that the attacker will attempt data exfiltration within the next 2-3 time windows. Key indicators: SYN flag ratio (SHAP +0.34), lateral SMB conn. (SHAP +0.28), accelerating attack tempo (SHAP +0.19).', evidence: null },
    { type: 'action', timestamp: 'NOW', text: 'ISOLATE host 192.168.1.12 from the network immediately. BLOCK all outbound traffic from 192.168.1.20. PRESERVE SSH session logs on 192.168.1.12 for forensic analysis.', evidence: null },
  ],

  rawLogStream: [
    { color: '#3b82f6', text: '[09:59:12] SYSTEM: Initiating Correlation Engine...' },
    { color: '#3b82f6', text: '[09:59:13] SYSTEM: Awaiting World Model Focus Signal...' },
    { color: '#cbd5e1', text: '[10:01:05] [NETFLOW] src=10.254.50.107 dst=192.168.1.10 port=22 proto=TCP flags=S bytes=74' },
    { color: '#cbd5e1', text: '[10:01:06] [NETFLOW] src=10.254.50.107 dst=192.168.1.11 port=22 proto=TCP flags=S bytes=74' },
    { color: '#eab308', text: '[10:01:08] [IDS] ALERT: High-rate SYN to port 22 from 10.254.50.107 — possible brute force' },
    { color: '#ef4444', text: '[10:03:00] [SYSTEM] WORLD MODEL SIGNAL: Attack Stage=Credential Access, P=0.55' },
    { color: '#3b82f6', text: '[10:03:01] [CORRELATION] Extracting graph subgraph around 10.254.50.107 (Window -5m to +1m)' },
    { color: '#cbd5e1', text: '[10:05:40] [WIN_EVT] EventID=4624 LogonType=3 user=admin src=10.254.50.107 dst=192.168.1.12 status=Success' },
    { color: '#eab308', text: '[10:05:45] [EDR] ALERT: psexec.exe executed on 192.168.1.12 (parent: services.exe)' },
    { color: '#ef4444', text: '[10:08:10] [SYSTEM] WORLD MODEL SIGNAL: Attack Stage=Lateral Movement, P=0.82' },
    { color: '#3b82f6', text: '[10:08:11] [CORRELATION] Correlating EDR alert with Auth Log ID 4624 → Graph edge formed.' },
    { color: '#10b981', text: '[10:08:15] [FUSION] Evidence confirms prediction. Boosting probability. Generating Narrative...' },
  ],

  graphNodes: [
    { id: 'attacker-main', type: 'attackNode', position: { x: 420, y: 270 }, data: { label: '10.254.50.107', sublabel: 'VMAL #1 · Windows', nodeType: 'attacker', icon: 'monitor' } },
    { id: 'atk-rpc-r', type: 'attackTypeNode', position: { x: 620, y: 80 }, data: { label: 'RPC Recon' } },
    { id: 'atk-ds', type: 'attackTypeNode', position: { x: 640, y: 185 }, data: { label: 'Data Smuggler' } },
    { id: 'atk-sg', type: 'attackTypeNode', position: { x: 650, y: 270 }, data: { label: 'Smash & Grab' } },
    { id: 'atk-fe-r', type: 'attackTypeNode', position: { x: 635, y: 360 }, data: { label: 'File Share Enum.' } },
    { id: 'atk-rpc-t', type: 'attackTypeNode', position: { x: 610, y: 455 }, data: { label: 'RPC Targeted Recon' } },
    { id: 'atk-fe-l', type: 'attackTypeNode', position: { x: 210, y: 165 }, data: { label: 'File Share Enum.' } },
    { id: 'atk-rpc-l', type: 'attackTypeNode', position: { x: 195, y: 375 }, data: { label: 'RPC Recon' } },
    { id: 'tg-22', type: 'targetGroupNode', position: { x: 850, y: 65 }, data: { count: 22, label: 'internal targets' } },
    { id: 'tg-2r', type: 'targetGroupNode', position: { x: 865, y: 170 }, data: { count: 2, label: 'internal targets' } },
    { id: 'tg-ext', type: 'attackNode', position: { x: 860, y: 255 }, data: { label: '10.254.20.107', nodeType: 'normal', icon: 'globe' } },
    { id: 'tg-25', type: 'targetGroupNode', position: { x: 860, y: 345 }, data: { count: 25, label: 'internal targets' } },
    { id: 'tg-3r', type: 'targetGroupNode', position: { x: 845, y: 440 }, data: { count: 3, label: 'internal targets' } },
    { id: 'tg-2l', type: 'targetGroupNode', position: { x: 10, y: 150 }, data: { count: 2, label: 'internal targets' } },
    { id: 'tg-3l', type: 'targetGroupNode', position: { x: 10, y: 360 }, data: { count: 3, label: 'internal targets' } },
  ],

  graphEdges: [
    { id: 'e-m-rpc-r', source: 'attacker-main', target: 'atk-rpc-r', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-m-ds', source: 'attacker-main', target: 'atk-ds', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-m-sg', source: 'attacker-main', target: 'atk-sg', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-m-fe-r', source: 'attacker-main', target: 'atk-fe-r', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-m-rpc-t', source: 'attacker-main', target: 'atk-rpc-t', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-m-fe-l', source: 'attacker-main', target: 'atk-fe-l', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-m-rpc-l', source: 'attacker-main', target: 'atk-rpc-l', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-rpc-r-22', source: 'atk-rpc-r', target: 'tg-22', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-ds-2r', source: 'atk-ds', target: 'tg-2r', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-sg-ext', source: 'atk-sg', target: 'tg-ext', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-fe-r-25', source: 'atk-fe-r', target: 'tg-25', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-rpc-t-3r', source: 'atk-rpc-t', target: 'tg-3r', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-fe-l-2l', source: 'atk-fe-l', target: 'tg-2l', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-rpc-l-3l', source: 'atk-rpc-l', target: 'tg-3l', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
  ],
};


// ─────────────────────────────────────────────────────────────
// SCENARIO B: CTU-13 — DNS Tunneling C2 Botnet Exfiltration
// ─────────────────────────────────────────────────────────────
const scenarioB = {
  name: 'Scenario B: Stealth Data Exfiltration (DNS Tunneling)',

  overviewStats: {
    totalFlows: 8341,
    maliciousFlows: 4122,
    activeAlerts: 5,
    dataset: 'CTU-13',
    subset: 'Scenario-10 (Botnet C2 + DNS Exfil)',
    rows: '8,341 flows',
    features: 64,
    duration: '30 min window',
    attackTypes: ['DNS-Tunneling', 'Botnet-C2', 'Exfiltration'],
    worldModelConfidence: 75,
    worldModelTrend: 'Stable — beaconing pattern consistent, predicted to reach 89% in 2 windows',
    infiltrationProbability: 0.75,
  },

  hosts: {
    attacker: {
      id: 'bot-1',
      ip: '10.50.2.11',
      hostname: 'BOT-HOST-01',
      os: 'Windows 10',
      sensor: 'Sensor stack 03',
      privilege: '3 - Medium',
      lastSeen: '2025-09-10T03:22:00Z',
      roles: ['Database Server', 'Compromised Bot'],
      entityImportance: 'High',
      attackRating: 9,
      velocity: 'Low (Stealthy)',
      urgencyScore: 87,
      priorityStatus: 'Under Investigation',
    },
    targets: [
      { id: 't1', ip: '185.220.101.45', hostname: 'C2-SERVER-EXT', os: 'Linux', role: 'C2 Server (External)' },
      { id: 't2', ip: '10.50.2.20', hostname: 'DB-CLUSTER-01', os: 'Linux', role: 'Database' },
      { id: 't3', ip: '10.50.2.21', hostname: 'DB-CLUSTER-02', os: 'Linux', role: 'Database' },
      { id: 't4', ip: '8.8.8.8', hostname: 'Google DNS (Abused)', os: 'N/A', role: 'DNS Resolver' },
    ],
  },

  attackProfile: {
    classification: 'Insider-Enabled Botnet',
    description: 'Compromised internal host is using DNS TXT records to tunnel data to an external C2 server, evading firewall rules.',
    positiveIndicators: ['DNS Tunneling', 'High Outbound DNS Volume', 'Beaconing (60s interval)', 'Data Staging', 'Encrypted Payload in TXT Records'],
  },

  mitreStages: [
    { id: 'INIT', name: 'Initial Compromise', icon: '🦠', status: 'confirmed', desc: 'Malware dropped via phishing', prob: null },
    { id: 'PERSIST', name: 'Persistence', icon: '⚓', status: 'confirmed', desc: 'Registry Run Key added', prob: null },
    { id: 'C2', name: 'Command & Control', icon: '📡', status: 'confirmed', desc: 'Beaconing every 60s via DNS', prob: null },
    { id: 'COLLECT', name: 'Collection', icon: '🗂️', status: 'current', desc: 'DB dump initiated', prob: '75%' },
    { id: 'EXFIL', name: 'Exfiltration', icon: '📤', status: 'predicted', desc: 'DNS TXT tunneling active', prob: '82%' },
    { id: 'IMPACT', name: 'Data Breach', icon: '💥', status: 'predicted', desc: 'Sensitive records at risk', prob: '89%' },
    { id: 'COVER', name: 'Cover Tracks', icon: '🧹', status: 'inactive', desc: 'Not yet observed', prob: null },
  ],

  urgencyTimeline: [
    { time: 'Sep 8', value: 5 },
    { time: 'Sep 8 12:00', value: 8 },
    { time: 'Sep 9', value: 12 },
    { time: 'Sep 9 12:00', value: 18 },
    { time: 'Sep 10', value: 30 },
    { time: 'Sep 10 06:00', value: 45 },
    { time: 'Sep 10 12:00', value: 60 },
    { time: 'Sep 10 18:00', value: 75 },
    { time: 'Sep 10 22:00', value: 87 },
    { time: 'Sep 11', value: 87 },
    { time: 'Sep 11 06:00', value: 87 },
    { time: 'Sep 11 12:00', value: 87 },
  ],

  detections: [
    { id: 'd1', category: 'C&C', categoryClass: 'cc', type: 'Botnet Beacon Detected (60s interval)', status: 'Active', statusClass: 'active', firstSeen: '2025-09-08T04:11:00Z', lastSeen: '2025-09-11T03:22:00Z' },
    { id: 'd2', category: 'Exfil', categoryClass: 'critical', type: 'DNS TXT Exfiltration — High Query Volume', status: 'Active', statusClass: 'active', firstSeen: '2025-09-10T02:30:00Z', lastSeen: '2025-09-11T03:22:00Z' },
    { id: 'd3', category: 'Exfil', categoryClass: 'critical', type: 'Large Payload in DNS TXT Records (>500B avg)', status: 'Active', statusClass: 'active', firstSeen: '2025-09-10T02:31:00Z', lastSeen: '2025-09-11T03:22:00Z' },
    { id: 'd4', category: 'Recon', categoryClass: 'recon', type: 'Internal DB Port Scan from BOT-HOST-01', status: 'Fixed', statusClass: 'fixed', firstSeen: '2025-09-09T22:15:00Z', lastSeen: '2025-09-09T23:00:00Z' },
    { id: 'd5', category: 'Info', categoryClass: 'info', type: 'Anomalous Process: dns-tunneler.exe on BOT-HOST-01', status: 'Active', statusClass: 'active', firstSeen: '2025-09-10T01:55:00Z', lastSeen: '2025-09-11T03:22:00Z' },
    { id: 'd6', category: 'Lateral', categoryClass: 'lateral', type: 'Unauthorized DB Query from BOT-HOST-01', status: 'Active', statusClass: 'active', firstSeen: '2025-09-10T03:00:00Z', lastSeen: '2025-09-11T02:45:00Z' },
  ],

  infiltrationTimeline: [
    { window: 't-10', time: '02:00', probability: 0.10, tactic: 'Benign', type: 'real' },
    { window: 't-9', time: '02:03', probability: 0.15, tactic: 'Benign', type: 'real' },
    { window: 't-8', time: '02:06', probability: 0.22, tactic: 'Persistence', type: 'real' },
    { window: 't-7', time: '02:09', probability: 0.31, tactic: 'C2 Beacon', type: 'real' },
    { window: 't-6', time: '02:12', probability: 0.40, tactic: 'C2 Beacon', type: 'real' },
    { window: 't-5', time: '02:15', probability: 0.48, tactic: 'Collection', type: 'real' },
    { window: 't-4', time: '02:18', probability: 0.55, tactic: 'Collection', type: 'real' },
    { window: 't-3', time: '02:21', probability: 0.62, tactic: 'DNS Tunnel', type: 'real' },
    { window: 't-2', time: '02:24', probability: 0.68, tactic: 'DNS Tunnel', type: 'real' },
    { window: 't-1', time: '02:27', probability: 0.72, tactic: 'DNS Tunnel', type: 'real' },
    { window: 'NOW', time: '02:30', probability: 0.75, tactic: 'Exfiltration', type: 'real' },
    { window: 't+1', time: '02:33', probability: 0.82, tactic: 'Exfiltration', type: 'predicted' },
    { window: 't+2', time: '02:36', probability: 0.89, tactic: 'Data Breach', type: 'predicted' },
    { window: 't+3', time: '02:39', probability: 0.93, tactic: 'Data Breach', type: 'predicted' },
  ],

  shapValues: [
    { feature: 'DNS_req_count', value: 0.52, direction: 'positive' },
    { feature: 'Avg_packet_size', value: 0.38, direction: 'positive' },
    { feature: 'Beacon_interval', value: 0.31, direction: 'positive' },
    { feature: 'TXT_record_ratio', value: 0.27, direction: 'positive' },
    { feature: 'UDP_53_ratio', value: 0.19, direction: 'positive' },
    { feature: 'Flow_entropy', value: 0.11, direction: 'positive' },
    { feature: 'HTTPS_ratio', value: -0.06, direction: 'negative' },
  ],

  explainabilityMeta: {
    calibratedProbability: '82%',
    confidenceLevel: 'HIGH',
    evidenceMatch: '4/5 Correlation',
  },

  networkLogs: [
    { id: 1, ts: '02:00:05.100', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'Query', bytes: 512, label: 'Benign', severity: 'low' },
    { id: 2, ts: '02:00:06.210', src: '8.8.8.8', dst: '10.50.2.11', proto: 'UDP', port: 53, flags: 'Response', bytes: 128, label: 'Benign', severity: 'low' },
    { id: 3, ts: '02:01:05.330', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'Query', bytes: 621, label: 'DNS-Tunneling', severity: 'high' },
    { id: 4, ts: '02:02:05.441', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'Query', bytes: 598, label: 'DNS-Tunneling', severity: 'high' },
    { id: 5, ts: '02:03:05.009', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'Query', bytes: 634, label: 'DNS-Tunneling', severity: 'high' },
    { id: 6, ts: '02:04:05.112', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'Query', bytes: 611, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 7, ts: '02:05:05.219', src: '10.50.2.11', dst: '185.220.101.45', proto: 'TCP', port: 443, flags: 'SYN', bytes: 74, label: 'Botnet-C2', severity: 'critical' },
    { id: 8, ts: '02:05:06.330', src: '185.220.101.45', dst: '10.50.2.11', proto: 'TCP', port: 443, flags: 'SYN-ACK', bytes: 74, label: 'Botnet-C2', severity: 'critical' },
    { id: 9, ts: '02:05:07.001', src: '10.50.2.11', dst: '185.220.101.45', proto: 'TCP', port: 443, flags: 'PSH-ACK', bytes: 2048, label: 'Botnet-C2', severity: 'critical' },
    { id: 10, ts: '02:06:05.445', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'Query', bytes: 689, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 11, ts: '02:10:05.112', src: '10.50.2.11', dst: '10.50.2.20', proto: 'TCP', port: 5432, flags: 'SYN', bytes: 74, label: 'Exfiltration', severity: 'critical' },
    { id: 12, ts: '02:10:06.223', src: '10.50.2.20', dst: '10.50.2.11', proto: 'TCP', port: 5432, flags: 'SYN-ACK', bytes: 74, label: 'Exfiltration', severity: 'high' },
    { id: 13, ts: '02:10:07.334', src: '10.50.2.11', dst: '10.50.2.20', proto: 'TCP', port: 5432, flags: 'PSH-ACK', bytes: 256, label: 'Exfiltration', severity: 'critical' },
    { id: 14, ts: '02:10:10.001', src: '10.50.2.20', dst: '10.50.2.11', proto: 'TCP', port: 5432, flags: 'PSH-ACK', bytes: 51200, label: 'Exfiltration', severity: 'critical' },
    { id: 15, ts: '02:11:05.110', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 845, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 16, ts: '02:12:05.225', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 890, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 17, ts: '02:13:05.339', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 912, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 18, ts: '02:14:02.001', src: '10.50.2.11', dst: '10.50.2.21', proto: 'TCP', port: 5432, flags: 'SYN', bytes: 74, label: 'Exfiltration', severity: 'high' },
    { id: 19, ts: '02:15:05.447', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 967, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 20, ts: '02:16:05.558', src: '10.50.2.11', dst: '185.220.101.45', proto: 'TCP', port: 443, flags: 'PSH-ACK', bytes: 8192, label: 'Botnet-C2', severity: 'critical' },
    { id: 21, ts: '02:17:05.001', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 1024, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 22, ts: '02:18:05.112', src: '185.220.101.45', dst: '10.50.2.11', proto: 'TCP', port: 443, flags: 'ACK', bytes: 54, label: 'Botnet-C2', severity: 'high' },
    { id: 23, ts: '02:19:05.223', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 1098, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 24, ts: '02:20:05.334', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 1134, label: 'DNS-Tunneling', severity: 'critical' },
    { id: 25, ts: '02:21:05.445', src: '10.50.2.11', dst: '8.8.8.8', proto: 'UDP', port: 53, flags: 'TXT-Query', bytes: 1201, label: 'DNS-Tunneling', severity: 'critical' },
  ],

  narrativeEntries: [
    { type: 'confirmed', timestamp: '02:01:05', text: 'Host 10.50.2.11 (BOT-HOST-01) began sending unusually large DNS TXT queries to 8.8.8.8 with 60-second beaconing intervals — consistent with known DNS tunneling C2 patterns.', evidence: 'DNS Query Log ID: dns_991 — avg payload 634B over 10,000+ queries in 30 min' },
    { type: 'confirmed', timestamp: '02:10:07', text: 'BOT-HOST-01 successfully queried internal DB-CLUSTER-01 (10.50.2.20) on port 5432 and received 50KB of database records — data staging in progress.', evidence: 'NetFlow record — 10.50.2.11:49234 → 10.50.2.20:5432, 51200 bytes [flow_id_7712]' },
    { type: 'confirmed', timestamp: '02:15:05', text: 'Staged DB records are being segmented and encoded into DNS TXT record payloads averaging 967B — 3x normal DNS response size.', evidence: 'Packet capture — TXT records contain base64-encoded binary data [pcap_id_3301]' },
    { type: 'predicted', timestamp: '+3 min', text: 'World Model forecasts with 82% confidence that full database dump will be exfiltrated via DNS tunnel within 3 time windows (~9 minutes). Key indicators: DNS_req_count (SHAP +0.52), Avg_packet_size (SHAP +0.38), Beacon_interval regularity (SHAP +0.31).', evidence: null },
    { type: 'action', timestamp: 'NOW', text: 'BLOCK all outbound UDP port 53 traffic from 10.50.2.11. ISOLATE BOT-HOST-01 from internal network segments. CAPTURE and analyze dns-tunneler.exe process memory. ALERT network team to the 185.220.101.45 C2 server.', evidence: null },
  ],

  rawLogStream: [
    { color: '#3b82f6', text: '[01:55:00] SYSTEM: Initiating Correlation Engine...' },
    { color: '#3b82f6', text: '[01:55:01] SYSTEM: Loading CTU-13 botnet signatures...' },
    { color: '#cbd5e1', text: '[02:01:05] [DNS] src=10.50.2.11 query=a1b2c3.malicious-c2.com type=TXT size=634B' },
    { color: '#eab308', text: '[02:01:06] [IDS] ALERT: Anomalous DNS TXT query size from 10.50.2.11 (634B vs 128B avg)' },
    { color: '#cbd5e1', text: '[02:02:05] [DNS] src=10.50.2.11 query=d4e5f6.malicious-c2.com type=TXT size=598B' },
    { color: '#eab308', text: '[02:02:06] [IDS] ALERT: Beaconing pattern detected — 60s interval from 10.50.2.11' },
    { color: '#ef4444', text: '[02:05:07] [SYSTEM] WORLD MODEL SIGNAL: Attack Stage=C2-Beacon, P=0.55' },
    { color: '#3b82f6', text: '[02:05:08] [CORRELATION] Matching beacon pattern to CTU-13 Scenario-10 signature' },
    { color: '#cbd5e1', text: '[02:10:10] [NETFLOW] src=10.50.2.11 dst=10.50.2.20 port=5432 bytes_out=51200 (DB Query)' },
    { color: '#ef4444', text: '[02:10:15] [SYSTEM] WORLD MODEL SIGNAL: Attack Stage=Data-Collection, P=0.75' },
    { color: '#eab308', text: '[02:15:05] [IDS] ALERT: Base64 encoded binary detected in DNS TXT payload — DNS Tunneling confirmed' },
    { color: '#10b981', text: '[02:15:10] [FUSION] DNS Tunneling + DB Access evidence corroborated. Generating Narrative...' },
  ],

  graphNodes: [
    { id: 'bot-main', type: 'attackNode', position: { x: 420, y: 250 }, data: { label: '10.50.2.11', sublabel: 'BOT-HOST-01 · Windows 10', nodeType: 'attacker', icon: 'monitor' } },
    { id: 'atk-dns', type: 'attackTypeNode', position: { x: 630, y: 100 }, data: { label: 'DNS Tunneling' } },
    { id: 'atk-c2', type: 'attackTypeNode', position: { x: 640, y: 250 }, data: { label: 'Botnet C2 Beacon' } },
    { id: 'atk-db', type: 'attackTypeNode', position: { x: 630, y: 400 }, data: { label: 'DB Exfiltration' } },
    { id: 'atk-dns-l', type: 'attackTypeNode', position: { x: 210, y: 150 }, data: { label: 'DNS Query Flood' } },
    { id: 'atk-persist', type: 'attackTypeNode', position: { x: 200, y: 360 }, data: { label: 'Registry Persistence' } },
    { id: 'tg-c2ext', type: 'attackNode', position: { x: 860, y: 80 }, data: { label: '185.220.101.45', sublabel: 'C2 Server (External)', nodeType: 'normal', icon: 'globe' } },
    { id: 'tg-dns', type: 'attackNode', position: { x: 870, y: 230 }, data: { label: '8.8.8.8', sublabel: 'Google DNS (Abused)', nodeType: 'normal', icon: 'globe' } },
    { id: 'tg-db1', type: 'targetGroupNode', position: { x: 860, y: 375 }, data: { count: 2, label: 'DB targets' } },
    { id: 'tg-8dns', type: 'targetGroupNode', position: { x: 10, y: 135 }, data: { count: 8, label: 'DNS resolvers' } },
    { id: 'tg-reg', type: 'targetGroupNode', position: { x: 10, y: 345 }, data: { count: 3, label: 'registry keys' } },
  ],

  graphEdges: [
    { id: 'e-bot-dns', source: 'bot-main', target: 'atk-dns', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-bot-c2', source: 'bot-main', target: 'atk-c2', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-bot-db', source: 'bot-main', target: 'atk-db', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-bot-dnsl', source: 'bot-main', target: 'atk-dns-l', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-bot-per', source: 'bot-main', target: 'atk-persist', animated: true, type: 'smoothstep', style: { stroke: '#ef4444', strokeWidth: 2 } },
    { id: 'e-dns-c2ext', source: 'atk-dns', target: 'tg-c2ext', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-c2-dns', source: 'atk-c2', target: 'tg-dns', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-db-db1', source: 'atk-db', target: 'tg-db1', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-dnsl-8dns', source: 'atk-dns-l', target: 'tg-8dns', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-per-reg', source: 'atk-persist', target: 'tg-reg', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
  ],
};


// ─────────────────────────────────────────────────────────────
// SCENARIO C: UNSW-NB15 — Insider Threat (Off-hours DB Access)
// ─────────────────────────────────────────────────────────────
const scenarioC = {
  name: 'Scenario C: Insider Threat (Anomalous Access)',

  overviewStats: {
    totalFlows: 5204,
    maliciousFlows: 312,
    activeAlerts: 3,
    dataset: 'UNSW-NB15',
    subset: 'Insider-Access Category (Off-hours)',
    rows: '5,204 flows',
    features: 49,
    duration: '45 min window',
    attackTypes: ['Anomalous-Access', 'Data-Theft', 'Insider-Threat'],
    worldModelConfidence: 65,
    worldModelTrend: 'Moderate — data access volumes rising, predicted to reach 78% in 4 windows',
    infiltrationProbability: 0.65,
  },

  hosts: {
    attacker: {
      id: 'insider-1',
      ip: '10.10.5.44',
      hostname: 'ALICE-WS (Finance)',
      os: 'Windows 11',
      sensor: 'Sensor stack 07',
      privilege: '2 - User',
      lastSeen: '2025-09-05T03:47:00Z',
      roles: ['Finance User', 'Employee Workstation'],
      entityImportance: 'Low',
      attackRating: 7,
      velocity: 'High (Burst)',
      urgencyScore: 65,
      priorityStatus: 'Flagged — Under Review',
    },
    targets: [
      { id: 't1', ip: '10.10.1.5', hostname: 'HR-DB-01', os: 'Linux', role: 'HR Database' },
      { id: 't2', ip: '10.10.1.6', hostname: 'PAYROLL-DB', os: 'Linux', role: 'Payroll Database' },
      { id: 't3', ip: '10.10.1.10', hostname: 'FILE-STAGING', os: 'Windows', role: 'Staging Server' },
      { id: 't4', ip: '192.168.100.5', hostname: 'PERSONAL-NAS', os: 'Linux', role: 'External (Personal NAS)' },
    ],
  },

  attackProfile: {
    classification: 'Insider Threat',
    description: 'Finance employee accessing HR and Payroll databases at 3 AM with unusually large SELECT * queries — indicative of data theft preparation.',
    positiveIndicators: ['Off-hours DB Access (3 AM)', 'Large SQL Query Volume', 'Cross-department Access', 'Outbound to Personal NAS', 'USB Activity Detected'],
  },

  mitreStages: [
    { id: 'RECON', name: 'Internal Recon', icon: '🔍', status: 'confirmed', desc: 'DB schema enumeration', prob: null },
    { id: 'AUTH', name: 'Valid Accounts', icon: '👤', status: 'confirmed', desc: 'Legit credentials used', prob: null },
    { id: 'COLLECT', name: 'Collection', icon: '🗂️', status: 'current', desc: 'SELECT * on HR tables', prob: '65%' },
    { id: 'STAGE', name: 'Staging', icon: '📦', status: 'predicted', desc: 'Copying to FILE-STAGING', prob: '72%' },
    { id: 'EXFIL', name: 'Exfiltration', icon: '📤', status: 'predicted', desc: 'Transfer to personal NAS', prob: '78%' },
    { id: 'COVER', name: 'Cover Tracks', icon: '🧹', status: 'inactive', desc: 'Log deletion possible', prob: null },
    { id: 'IMPACT', name: 'Data Leak', icon: '💥', status: 'inactive', desc: 'Regulatory risk', prob: null },
  ],

  urgencyTimeline: [
    { time: 'Sep 5 00:00', value: 0 },
    { time: 'Sep 5 01:00', value: 2 },
    { time: 'Sep 5 02:00', value: 5 },
    { time: 'Sep 5 02:30', value: 10 },
    { time: 'Sep 5 03:00', value: 35 },
    { time: 'Sep 5 03:15', value: 55 },
    { time: 'Sep 5 03:30', value: 65 },
    { time: 'Sep 5 03:47', value: 65 },
    { time: 'Sep 5 04:00', value: 65 },
    { time: 'Sep 5 05:00', value: 65 },
    { time: 'Sep 5 06:00', value: 60 },
    { time: 'Sep 5 08:00', value: 55 },
  ],

  detections: [
    { id: 'd1', category: 'Anomaly', categoryClass: 'high', type: 'Off-hours Login (03:12 AM) — ALICE-WS', status: 'Active', statusClass: 'active', firstSeen: '2025-09-05T03:12:00Z', lastSeen: '2025-09-05T03:47:00Z' },
    { id: 'd2', category: 'Anomaly', categoryClass: 'critical', type: 'Cross-dept DB Access: Finance User → HR-DB-01', status: 'Active', statusClass: 'active', firstSeen: '2025-09-05T03:15:00Z', lastSeen: '2025-09-05T03:47:00Z' },
    { id: 'd3', category: 'Exfil', categoryClass: 'critical', type: 'Large SQL SELECT * on employees table (4,800 rows)', status: 'Active', statusClass: 'active', firstSeen: '2025-09-05T03:18:00Z', lastSeen: '2025-09-05T03:47:00Z' },
    { id: 'd4', category: 'Info', categoryClass: 'info', type: 'USB Device Connected to ALICE-WS at 03:22 AM', status: 'Fixed', statusClass: 'fixed', firstSeen: '2025-09-05T03:22:00Z', lastSeen: '2025-09-05T03:45:00Z' },
    { id: 'd5', category: 'Anomaly', categoryClass: 'high', type: 'Outbound Traffic to Personal NAS 192.168.100.5', status: 'Active', statusClass: 'active', firstSeen: '2025-09-05T03:40:00Z', lastSeen: '2025-09-05T03:47:00Z' },
  ],

  infiltrationTimeline: [
    { window: 't-10', time: '02:57', probability: 0.05, tactic: 'Benign', type: 'real' },
    { window: 't-9', time: '03:00', probability: 0.08, tactic: 'Benign', type: 'real' },
    { window: 't-8', time: '03:03', probability: 0.15, tactic: 'Login Anomaly', type: 'real' },
    { window: 't-7', time: '03:06', probability: 0.24, tactic: 'Login Anomaly', type: 'real' },
    { window: 't-6', time: '03:09', probability: 0.30, tactic: 'Auth — Valid Creds', type: 'real' },
    { window: 't-5', time: '03:12', probability: 0.38, tactic: 'Internal Recon', type: 'real' },
    { window: 't-4', time: '03:15', probability: 0.45, tactic: 'DB Access', type: 'real' },
    { window: 't-3', time: '03:18', probability: 0.52, tactic: 'Collection', type: 'real' },
    { window: 't-2', time: '03:21', probability: 0.59, tactic: 'Collection', type: 'real' },
    { window: 't-1', time: '03:24', probability: 0.63, tactic: 'Staging', type: 'real' },
    { window: 'NOW', time: '03:27', probability: 0.65, tactic: 'Staging', type: 'real' },
    { window: 't+1', time: '03:30', probability: 0.70, tactic: 'Exfiltration', type: 'predicted' },
    { window: 't+2', time: '03:33', probability: 0.74, tactic: 'Exfiltration', type: 'predicted' },
    { window: 't+3', time: '03:36', probability: 0.78, tactic: 'Data Leak', type: 'predicted' },
  ],

  shapValues: [
    { feature: 'Hour_of_day', value: 0.55, direction: 'positive' },
    { feature: 'Bytes_transferred', value: 0.41, direction: 'positive' },
    { feature: 'Query_count', value: 0.33, direction: 'positive' },
    { feature: 'Cross_dept_access', value: 0.28, direction: 'positive' },
    { feature: 'USB_activity', value: 0.22, direction: 'positive' },
    { feature: 'Login_freq', value: 0.14, direction: 'positive' },
    { feature: 'Session_duration', value: -0.08, direction: 'negative' },
  ],

  explainabilityMeta: {
    calibratedProbability: '72%',
    confidenceLevel: 'MEDIUM',
    evidenceMatch: '4/5 Correlation',
  },

  networkLogs: [
    { id: 1, ts: '03:12:01.110', src: '10.10.5.44', dst: '10.10.1.5', proto: 'TCP', port: 5432, flags: 'SYN', bytes: 74, label: 'Anomaly', severity: 'medium' },
    { id: 2, ts: '03:12:01.220', src: '10.10.1.5', dst: '10.10.5.44', proto: 'TCP', port: 5432, flags: 'SYN-ACK', bytes: 74, label: 'Anomaly', severity: 'low' },
    { id: 3, ts: '03:12:01.330', src: '10.10.5.44', dst: '10.10.1.5', proto: 'TCP', port: 5432, flags: 'ACK', bytes: 54, label: 'Anomaly', severity: 'low' },
    { id: 4, ts: '03:12:05.001', src: '10.10.5.44', dst: '10.10.1.5', proto: 'TCP', port: 5432, flags: 'PSH-ACK', bytes: 312, label: 'Insider-Threat', severity: 'high' },
    { id: 5, ts: '03:12:06.112', src: '10.10.1.5', dst: '10.10.5.44', proto: 'TCP', port: 5432, flags: 'PSH-ACK', bytes: 153600, label: 'Insider-Threat', severity: 'critical' },
    { id: 6, ts: '03:15:01.224', src: '10.10.5.44', dst: '10.10.1.5', proto: 'TCP', port: 5432, flags: 'PSH-ACK', bytes: 284, label: 'Insider-Threat', severity: 'high' },
    { id: 7, ts: '03:15:02.335', src: '10.10.1.5', dst: '10.10.5.44', proto: 'TCP', port: 5432, flags: 'PSH-ACK', bytes: 204800, label: 'Insider-Threat', severity: 'critical' },
    { id: 8, ts: '03:18:01.446', src: '10.10.5.44', dst: '10.10.1.6', proto: 'TCP', port: 3306, flags: 'SYN', bytes: 74, label: 'Insider-Threat', severity: 'critical' },
    { id: 9, ts: '03:18:02.557', src: '10.10.1.6', dst: '10.10.5.44', proto: 'TCP', port: 3306, flags: 'SYN-ACK', bytes: 74, label: 'Insider-Threat', severity: 'high' },
    { id: 10, ts: '03:18:05.001', src: '10.10.5.44', dst: '10.10.1.6', proto: 'TCP', port: 3306, flags: 'PSH-ACK', bytes: 196, label: 'Insider-Threat', severity: 'critical' },
    { id: 11, ts: '03:18:06.112', src: '10.10.1.6', dst: '10.10.5.44', proto: 'TCP', port: 3306, flags: 'PSH-ACK', bytes: 98304, label: 'Insider-Threat', severity: 'critical' },
    { id: 12, ts: '03:22:01.223', src: '10.10.5.44', dst: '10.10.1.10', proto: 'TCP', port: 445, flags: 'SYN', bytes: 74, label: 'Insider-Threat', severity: 'high' },
    { id: 13, ts: '03:22:02.334', src: '10.10.1.10', dst: '10.10.5.44', proto: 'TCP', port: 445, flags: 'SYN-ACK', bytes: 74, label: 'Anomaly', severity: 'medium' },
    { id: 14, ts: '03:22:05.001', src: '10.10.5.44', dst: '10.10.1.10', proto: 'TCP', port: 445, flags: 'PSH-ACK', bytes: 245760, label: 'Insider-Threat', severity: 'critical' },
    { id: 15, ts: '03:40:01.112', src: '10.10.5.44', dst: '192.168.100.5', proto: 'TCP', port: 22, flags: 'SYN', bytes: 74, label: 'Exfiltration', severity: 'critical' },
    { id: 16, ts: '03:40:02.223', src: '192.168.100.5', dst: '10.10.5.44', proto: 'TCP', port: 22, flags: 'SYN-ACK', bytes: 74, label: 'Exfiltration', severity: 'critical' },
    { id: 17, ts: '03:40:10.334', src: '10.10.5.44', dst: '192.168.100.5', proto: 'TCP', port: 22, flags: 'PSH-ACK', bytes: 512000, label: 'Exfiltration', severity: 'critical' },
    { id: 18, ts: '03:41:01.445', src: '10.10.5.44', dst: '192.168.100.5', proto: 'TCP', port: 22, flags: 'PSH-ACK', bytes: 512000, label: 'Exfiltration', severity: 'critical' },
    { id: 19, ts: '03:41:30.556', src: '192.168.100.5', dst: '10.10.5.44', proto: 'TCP', port: 22, flags: 'ACK', bytes: 54, label: 'Exfiltration', severity: 'high' },
    { id: 20, ts: '03:42:01.667', src: '10.10.5.44', dst: '192.168.100.5', proto: 'TCP', port: 22, flags: 'PSH-ACK', bytes: 512000, label: 'Exfiltration', severity: 'critical' },
    { id: 21, ts: '03:43:05.778', src: '10.10.5.44', dst: '10.10.1.5', proto: 'TCP', port: 5432, flags: 'PSH-ACK', bytes: 148, label: 'Insider-Threat', severity: 'high' },
    { id: 22, ts: '03:44:01.889', src: '10.10.5.44', dst: '192.168.100.5', proto: 'TCP', port: 22, flags: 'PSH-ACK', bytes: 512000, label: 'Exfiltration', severity: 'critical' },
    { id: 23, ts: '03:45:02.001', src: '10.10.5.44', dst: '10.10.1.10', proto: 'TCP', port: 445, flags: 'FIN-ACK', bytes: 54, label: 'Anomaly', severity: 'medium' },
    { id: 24, ts: '03:46:01.112', src: '10.10.5.44', dst: '192.168.100.5', proto: 'TCP', port: 22, flags: 'PSH-ACK', bytes: 512000, label: 'Exfiltration', severity: 'critical' },
    { id: 25, ts: '03:47:00.223', src: '10.10.5.44', dst: '192.168.100.5', proto: 'TCP', port: 22, flags: 'FIN-ACK', bytes: 54, label: 'Exfiltration', severity: 'high' },
  ],

  narrativeEntries: [
    { type: 'confirmed', timestamp: '03:12:01', text: 'Finance user Alice (10.10.5.44, ALICE-WS) logged into HR-DB-01 (10.10.1.5) at 03:12 AM via Postgres port 5432 — outside normal working hours (9 AM – 6 PM). Auth log confirms legitimate credentials.', evidence: 'Auth Log ID: auth_510 — logon_time=03:12:01, user=alice@finance, host=HR-DB-01' },
    { type: 'confirmed', timestamp: '03:12:06', text: 'Alice executed a SELECT * query on the "employees" table returning 4,800 rows totalling 150KB — 95th percentile query size for this user (normal avg: 8KB). Similar query on payroll_records at 03:18 returned 96KB.', evidence: 'DB Audit Log — query_id: db_audit_7732, rows_returned: 4800, bytes: 153600' },
    { type: 'confirmed', timestamp: '03:40:10', text: 'Staged files (estimated 2GB total) are being transferred to 192.168.100.5 via SSH/SCP — IP belongs to a personal NAS device not registered on the corporate asset inventory.', evidence: 'NetFlow — 10.10.5.44:46211 → 192.168.100.5:22, 6 transfers × 512KB [flow_id_5589]' },
    { type: 'predicted', timestamp: '+4 min', text: 'World Model predicts with 72% confidence that the full data transfer will complete within the next 4 time windows (~12 minutes). Key indicators: Hour_of_day (SHAP +0.55), Bytes_transferred (SHAP +0.41), Cross_dept_access (SHAP +0.28).', evidence: null },
    { type: 'action', timestamp: 'NOW', text: 'TERMINATE Alice\'s active sessions immediately. BLOCK all outbound traffic from 10.10.5.44 to 192.168.100.5. PRESERVE DB audit logs and USB device forensic image. NOTIFY HR and Legal teams. REVOKE alice@finance credentials pending investigation.', evidence: null },
  ],

  rawLogStream: [
    { color: '#3b82f6', text: '[03:00:00] SYSTEM: Initiating Correlation Engine...' },
    { color: '#3b82f6', text: '[03:00:01] SYSTEM: Loading UNSW-NB15 insider threat signatures...' },
    { color: '#eab308', text: '[03:12:01] [UEBA] ALERT: Login anomaly — alice@finance authenticated at 03:12 AM (off-hours threshold: 22:00)' },
    { color: '#cbd5e1', text: '[03:12:05] [DB_AUDIT] user=alice@finance db=HR_DB query="SELECT * FROM employees" rows=4800 bytes=153600' },
    { color: '#ef4444', text: '[03:12:10] [SYSTEM] WORLD MODEL SIGNAL: Anomaly Score=0.45 — Cross-dept DB access detected' },
    { color: '#3b82f6', text: '[03:12:11] [CORRELATION] Flagging ALICE-WS session for enhanced monitoring' },
    { color: '#eab308', text: '[03:18:06] [DB_AUDIT] user=alice@finance db=PAYROLL_DB query="SELECT * FROM payroll_records" rows=2400 bytes=98304' },
    { color: '#ef4444', text: '[03:18:10] [SYSTEM] WORLD MODEL SIGNAL: Attack Stage=Collection, P=0.65' },
    { color: '#cbd5e1', text: '[03:22:01] [EDR] USB device connected to ALICE-WS (VID:PID 0781:5583 — SanDisk 64GB)' },
    { color: '#eab308', text: '[03:40:10] [NETFLOW] src=10.10.5.44 dst=192.168.100.5 port=22 bytes=512000 (SCP transfer)' },
    { color: '#ef4444', text: '[03:40:15] [IDS] ALERT: Outbound data transfer to unregistered external IP 192.168.100.5' },
    { color: '#10b981', text: '[03:40:20] [FUSION] Insider access + USB + exfil evidence corroborated. Generating Narrative...' },
  ],

  graphNodes: [
    { id: 'alice-main', type: 'attackNode', position: { x: 420, y: 250 }, data: { label: '10.10.5.44', sublabel: 'ALICE-WS · Finance', nodeType: 'attacker', icon: 'monitor' } },
    { id: 'atk-hrdb', type: 'attackTypeNode', position: { x: 630, y: 90 }, data: { label: 'HR DB Access' } },
    { id: 'atk-payroll', type: 'attackTypeNode', position: { x: 645, y: 200 }, data: { label: 'Payroll DB Query' } },
    { id: 'atk-usb', type: 'attackTypeNode', position: { x: 640, y: 310 }, data: { label: 'USB Data Copy' } },
    { id: 'atk-nas', type: 'attackTypeNode', position: { x: 630, y: 415 }, data: { label: 'NAS Exfiltration' } },
    { id: 'atk-stage', type: 'attackTypeNode', position: { x: 210, y: 150 }, data: { label: 'File Staging' } },
    { id: 'atk-recon', type: 'attackTypeNode', position: { x: 195, y: 355 }, data: { label: 'DB Schema Recon' } },
    { id: 'tg-hr', type: 'targetGroupNode', position: { x: 860, y: 75 }, data: { count: 1, label: 'HR DB target' } },
    { id: 'tg-pay', type: 'targetGroupNode', position: { x: 865, y: 185 }, data: { count: 1, label: 'Payroll DB target' } },
    { id: 'tg-usb-dev', type: 'targetGroupNode', position: { x: 855, y: 295 }, data: { count: 1, label: 'USB device' } },
    { id: 'tg-nas-ext', type: 'attackNode', position: { x: 850, y: 400 }, data: { label: '192.168.100.5', sublabel: 'Personal NAS (External)', nodeType: 'normal', icon: 'globe' } },
    { id: 'tg-staging', type: 'targetGroupNode', position: { x: 10, y: 135 }, data: { count: 2, label: 'staging files' } },
    { id: 'tg-tables', type: 'targetGroupNode', position: { x: 10, y: 340 }, data: { count: 6, label: 'DB tables' } },
  ],

  graphEdges: [
    { id: 'e-al-hr', source: 'alice-main', target: 'atk-hrdb', animated: true, type: 'smoothstep', style: { stroke: '#eab308', strokeWidth: 2 } },
    { id: 'e-al-pay', source: 'alice-main', target: 'atk-payroll', animated: true, type: 'smoothstep', style: { stroke: '#eab308', strokeWidth: 2 } },
    { id: 'e-al-usb', source: 'alice-main', target: 'atk-usb', animated: true, type: 'smoothstep', style: { stroke: '#eab308', strokeWidth: 2 } },
    { id: 'e-al-nas', source: 'alice-main', target: 'atk-nas', animated: true, type: 'smoothstep', style: { stroke: '#eab308', strokeWidth: 2 } },
    { id: 'e-al-stage', source: 'alice-main', target: 'atk-stage', animated: true, type: 'smoothstep', style: { stroke: '#eab308', strokeWidth: 2 } },
    { id: 'e-al-recon', source: 'alice-main', target: 'atk-recon', animated: true, type: 'smoothstep', style: { stroke: '#eab308', strokeWidth: 2 } },
    { id: 'e-hr-tg', source: 'atk-hrdb', target: 'tg-hr', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-pay-tg', source: 'atk-payroll', target: 'tg-pay', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-usb-tg', source: 'atk-usb', target: 'tg-usb-dev', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-nas-tg', source: 'atk-nas', target: 'tg-nas-ext', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-stage-tg', source: 'atk-stage', target: 'tg-staging', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
    { id: 'e-recon-tg', source: 'atk-recon', target: 'tg-tables', type: 'smoothstep', style: { stroke: '#94a3b8', strokeWidth: 1.5 } },
  ],
};


// ─────────────────────────────────────────────────────────────
// Export the scenarios map
// ─────────────────────────────────────────────────────────────
export const scenarios = {
  'A_BRUTE_FORCE': scenarioA,
  'B_EXFILTRATION': scenarioB,
  'C_INSIDER': scenarioC,
};

// Re-export formatDate utility
export function formatDate(isoString) {
  const d = new Date(isoString);
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const day = d.getDate();
  const suffix = day === 1 || day === 21 || day === 31 ? 'st' : day === 2 || day === 22 ? 'nd' : day === 3 || day === 23 ? 'rd' : 'th';
  const hours = d.getHours().toString().padStart(2, '0');
  const mins = d.getMinutes().toString().padStart(2, '0');
  return `${months[d.getMonth()]} ${day}${suffix} ${d.getFullYear()} ${hours}:${mins}`;
}
