// =============================================================
// SENTINEL — Mock Attack Scenario Data
// A realistic SSH brute-force → lateral movement → exfiltration
// scenario that drives the entire dashboard
// =============================================================

// --- HOST DATA ---
export const hosts = {
  attacker: {
    id: 'attacker-1',
    ip: '10.254.50.107',
    hostname: 'VMAL #1',
    os: 'Windows',
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
    { id: 'target-1', ip: '192.168.1.10', hostname: 'WEB-SVR-01', os: 'Linux', role: 'Web Server' },
    { id: 'target-2', ip: '192.168.1.11', hostname: 'WEB-SVR-02', os: 'Linux', role: 'Web Server' },
    { id: 'target-3', ip: '192.168.1.12', hostname: 'APP-SVR-01', os: 'Windows', role: 'App Server' },
    { id: 'target-4', ip: '192.168.1.15', hostname: 'DB-SVR-01', os: 'Linux', role: 'Database' },
    { id: 'target-5', ip: '192.168.1.20', hostname: 'FILE-SVR-01', os: 'Windows', role: 'File Server' },
    { id: 'target-6', ip: '192.168.1.25', hostname: 'DC-01', os: 'Windows', role: 'Domain Controller' },
    { id: 'target-7', ip: '192.168.1.30', hostname: 'MAIL-SVR', os: 'Linux', role: 'Mail Server' },
    { id: 'target-8', ip: '192.168.1.35', hostname: 'PROXY-01', os: 'Linux', role: 'Proxy' },
    { id: 'target-9', ip: '10.254.20.107', hostname: 'EXT-HOST', os: 'Windows', role: 'External' },
  ],
};

// --- ATTACK PROFILE ---
export const attackProfile = {
  classification: 'External Adversary',
  description: 'Active behaviors associated with sophisticated, objective-oriented adversary.',
  positiveIndicators: [
    'Data Smuggler',
    'File Share Enumeration',
    'Port Scan',
    'RDP Recon',
    'RPC Recon',
    'Hidden HTTP Tunnel',
    'SMB Account Scan',
  ],
};

// --- DETECTIONS ---
export const detections = [
  {
    id: 'det-1',
    category: 'Info',
    categoryClass: 'info',
    type: 'New Host Role',
    status: 'Active',
    statusClass: 'active',
    firstSeen: '2025-08-29T17:29:00Z',
    lastSeen: '2025-08-29T17:29:00Z',
    expanded: false,
  },
  {
    id: 'det-2',
    category: 'C&C',
    categoryClass: 'cc',
    type: 'Hidden HTTP Tunnel',
    status: 'Inactive',
    statusClass: 'inactive',
    firstSeen: '2025-08-15T15:43:00Z',
    lastSeen: '2025-08-28T12:50:00Z',
    expanded: false,
  },
  {
    id: 'det-3',
    category: 'C&C',
    categoryClass: 'cc',
    type: 'Suspect HTTP Activity: PowerShell Empire',
    status: 'Inactive',
    statusClass: 'inactive',
    firstSeen: '2025-08-15T15:43:00Z',
    lastSeen: '2025-08-28T12:49:00Z',
    expanded: false,
  },
  {
    id: 'det-4',
    category: 'C&C',
    categoryClass: 'cc',
    type: 'Hidden HTTPS Tunnel',
    status: 'Inactive',
    statusClass: 'inactive',
    firstSeen: '2025-08-15T15:46:00Z',
    lastSeen: '2025-08-28T11:57:00Z',
    expanded: false,
  },
  {
    id: 'det-5',
    category: 'Recon',
    categoryClass: 'recon',
    type: 'SMB Account Scan',
    status: 'Fixed',
    statusClass: 'fixed',
    firstSeen: '2025-08-22T13:48:00Z',
    lastSeen: '2025-08-25T21:27:00Z',
    expanded: false,
  },
  {
    id: 'det-6',
    category: 'Recon',
    categoryClass: 'recon',
    type: 'Expected Activity For 50-107 (SMB Account Scan)',
    status: 'Filtered',
    statusClass: 'filtered',
    firstSeen: '2025-08-22T13:48:00Z',
    lastSeen: '2025-08-25T21:27:00Z',
    expanded: false,
  },
  {
    id: 'det-7',
    category: 'Lateral',
    categoryClass: 'lateral',
    type: 'File Share Enumeration',
    status: 'Active',
    statusClass: 'active',
    firstSeen: '2025-08-22T06:45:00Z',
    lastSeen: '2025-09-02T17:48:00Z',
    expanded: false,
  },
  {
    id: 'det-8',
    category: 'Lateral',
    categoryClass: 'lateral',
    type: 'RPC Targeted Recon',
    status: 'Active',
    statusClass: 'active',
    firstSeen: '2025-08-22T06:51:00Z',
    lastSeen: '2025-09-02T17:45:00Z',
    expanded: false,
  },
];

// --- URGENCY TIMELINE DATA ---
export const urgencyTimeline = [
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
  { time: 'Sep 18 19:00', value: 100 },
];

// --- INFILTRATION PROBABILITY TIMELINE ---
export const infiltrationTimeline = [
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
];

// --- MITRE STAGE PROGRESSION ---
export const mitreStages = [
  { id: 'TA0043', name: 'Recon', shortName: 'RECON', status: 'confirmed', icon: '🔍', probability: null },
  { id: 'TA0001', name: 'Initial Access', shortName: 'INIT', status: 'confirmed', icon: '🚪', probability: null },
  { id: 'TA0006', name: 'Credential Access', shortName: 'CRED', status: 'confirmed', icon: '🔑', probability: null },
  { id: 'TA0008', name: 'Lateral Movement', shortName: 'LATERAL', status: 'current', icon: '⚡', probability: 0.82 },
  { id: 'TA0011', name: 'Command & Control', shortName: 'C2', status: 'predicted', icon: '📡', probability: 0.87 },
  { id: 'TA0010', name: 'Exfiltration', shortName: 'EXFIL', status: 'predicted', icon: '📤', probability: 0.91 },
  { id: 'TA0040', name: 'Impact', shortName: 'IMPACT', status: 'inactive', icon: '💥', probability: null },
];

// --- NARRATIVE ENTRIES ---
export const narrativeEntries = [
  {
    type: 'confirmed',
    timestamp: '14:02:15',
    text: 'Host 10.254.50.107 initiated a high-volume SSH brute force attack targeting the 192.168.1.0/24 subnet. 850 SYN packets to port 22 across 15 destinations in 60 seconds.',
    evidence: 'Flow record — 850 SYN packets to port 22 across 15 destinations [Log: flow_id_8834]',
  },
  {
    type: 'confirmed',
    timestamp: '14:03:10',
    text: 'Attacker successfully authenticated to 192.168.1.12 (APP-SVR-01) via SSH after 47 failed attempts.',
    evidence: 'Windows Event 4624 — Successful logon, user "admin", source 10.254.50.107 [Log: evt_id_12847]',
  },
  {
    type: 'confirmed',
    timestamp: '14:03:25',
    text: 'Compromised host 192.168.1.12 initiated SMB connection to 192.168.1.20 (FILE-SVR-01) — lateral movement detected.',
    evidence: 'Flow record — 192.168.1.12:49512 → 192.168.1.20:445 [Log: flow_id_9021]',
  },
  {
    type: 'predicted',
    timestamp: '+2 min',
    text: 'World Model forecasts with 87% confidence that the attacker will attempt data exfiltration within the next 2-3 time windows (~2-3 minutes). Key indicators: SYN flag ratio (SHAP +0.34), lateral connection to file server on SMB (SHAP +0.28), accelerating attack tempo (SHAP +0.19).',
    evidence: null,
  },
  {
    type: 'action',
    timestamp: 'NOW',
    text: 'ISOLATE host 192.168.1.12 from the network immediately. BLOCK all outbound traffic from 192.168.1.20. PRESERVE SSH session logs on 192.168.1.12 for forensic analysis.',
    evidence: null,
  },
];

// --- SHAP VALUES ---
export const shapValues = [
  { feature: 'SYN flag ratio', value: 0.34, direction: 'positive' },
  { feature: 'Lateral SMB conn.', value: 0.28, direction: 'positive' },
  { feature: 'Attack tempo', value: 0.19, direction: 'positive' },
  { feature: 'Port 22 focus', value: 0.15, direction: 'positive' },
  { feature: 'Flow duration', value: 0.09, direction: 'positive' },
  { feature: 'Unique dst ports', value: 0.07, direction: 'positive' },
  { feature: 'Packet size var', value: -0.04, direction: 'negative' },
];

// --- ATTACK GRAPH NODES (for ReactFlow) ---
export const graphNodes = [
  // Central attacker
  {
    id: 'attacker-main',
    type: 'attackNode',
    position: { x: 400, y: 280 },
    data: {
      label: '10.254.50.107',
      sublabel: 'VMAL #1 windows',
      nodeType: 'attacker',
      icon: 'monitor',
    },
  },
  // Attack types (edge nodes with icons)
  {
    id: 'attack-rpc-recon',
    type: 'attackTypeNode',
    position: { x: 550, y: 100 },
    data: { label: 'RPC Recon', attackType: true },
  },
  {
    id: 'attack-data-smuggler',
    type: 'attackTypeNode',
    position: { x: 580, y: 200 },
    data: { label: 'Data Smuggler', attackType: true },
  },
  {
    id: 'attack-smash-grab',
    type: 'attackTypeNode',
    position: { x: 580, y: 280 },
    data: { label: 'Smash and Grab', attackType: true },
  },
  {
    id: 'attack-file-enum-r',
    type: 'attackTypeNode',
    position: { x: 570, y: 360 },
    data: { label: 'File Share Enumeration', attackType: true },
  },
  {
    id: 'attack-rpc-targeted',
    type: 'attackTypeNode',
    position: { x: 540, y: 440 },
    data: { label: 'RPC Targeted Recon', attackType: true },
  },
  {
    id: 'attack-file-enum-l',
    type: 'attackTypeNode',
    position: { x: 220, y: 180 },
    data: { label: 'File Share Enumeration', attackType: true },
  },
  {
    id: 'attack-rpc-recon-l',
    type: 'attackTypeNode',
    position: { x: 200, y: 380 },
    data: { label: 'RPC Recon', attackType: true },
  },
  // Target groups (right side)
  {
    id: 'target-group-22',
    type: 'targetGroupNode',
    position: { x: 740, y: 85 },
    data: { count: 22, label: 'internal targets' },
  },
  {
    id: 'target-group-2r',
    type: 'targetGroupNode',
    position: { x: 740, y: 185 },
    data: { count: 2, label: 'internal targets' },
  },
  {
    id: 'target-ext',
    type: 'attackNode',
    position: { x: 740, y: 265 },
    data: {
      label: '10.254.20.107',
      nodeType: 'normal',
      icon: 'globe',
    },
  },
  {
    id: 'target-group-25',
    type: 'targetGroupNode',
    position: { x: 740, y: 345 },
    data: { count: 25, label: 'internal targets' },
  },
  {
    id: 'target-group-3r',
    type: 'targetGroupNode',
    position: { x: 740, y: 425 },
    data: { count: 3, label: 'internal targets' },
  },
  // Target groups (left side)
  {
    id: 'target-group-2l',
    type: 'targetGroupNode',
    position: { x: 20, y: 165 },
    data: { count: 2, label: 'internal targets' },
  },
  {
    id: 'target-group-3l',
    type: 'targetGroupNode',
    position: { x: 20, y: 365 },
    data: { count: 3, label: 'internal targets' },
  },
];

// --- ATTACK GRAPH EDGES ---
export const graphEdges = [
  // Attacker to attack types (right)
  { id: 'e-att-rpc', source: 'attacker-main', target: 'attack-rpc-recon', animated: true, style: { stroke: '#ef4444' } },
  { id: 'e-att-ds', source: 'attacker-main', target: 'attack-data-smuggler', animated: true, style: { stroke: '#ef4444' } },
  { id: 'e-att-sg', source: 'attacker-main', target: 'attack-smash-grab', animated: true, style: { stroke: '#ef4444' } },
  { id: 'e-att-fe', source: 'attacker-main', target: 'attack-file-enum-r', animated: true, style: { stroke: '#ef4444' } },
  { id: 'e-att-rt', source: 'attacker-main', target: 'attack-rpc-targeted', animated: true, style: { stroke: '#ef4444' } },
  // Attacker to attack types (left)
  { id: 'e-att-fel', source: 'attacker-main', target: 'attack-file-enum-l', animated: true, style: { stroke: '#ef4444' } },
  { id: 'e-att-rrl', source: 'attacker-main', target: 'attack-rpc-recon-l', animated: true, style: { stroke: '#ef4444' } },
  // Attack types to target groups (right)
  { id: 'e-rpc-tg22', source: 'attack-rpc-recon', target: 'target-group-22', type: 'default' },
  { id: 'e-ds-tg2', source: 'attack-data-smuggler', target: 'target-group-2r', type: 'default' },
  { id: 'e-sg-ext', source: 'attack-smash-grab', target: 'target-ext', type: 'default' },
  { id: 'e-fe-tg25', source: 'attack-file-enum-r', target: 'target-group-25', type: 'default' },
  { id: 'e-rt-tg3', source: 'attack-rpc-targeted', target: 'target-group-3r', type: 'default' },
  // Attack types to target groups (left)
  { id: 'e-fel-tg2l', source: 'attack-file-enum-l', target: 'target-group-2l', type: 'default' },
  { id: 'e-rrl-tg3l', source: 'attack-rpc-recon-l', target: 'target-group-3l', type: 'default' },
];

// --- HELPER: Format date ---
export function formatDate(isoString) {
  const d = new Date(isoString);
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const day = d.getDate();
  const suffix = day === 1 || day === 21 || day === 31 ? 'st' : day === 2 || day === 22 ? 'nd' : day === 3 || day === 23 ? 'rd' : 'th';
  const hours = d.getHours().toString().padStart(2, '0');
  const mins = d.getMinutes().toString().padStart(2, '0');
  return `${months[d.getMonth()]} ${day}${suffix} ${d.getFullYear()} ${hours}:${mins}`;
}
