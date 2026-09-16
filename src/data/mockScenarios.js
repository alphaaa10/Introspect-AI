import { hosts, attackProfile, graphNodes as initialNodes, graphEdges as initialEdges, urgencyTimeline, detections, infiltrationTimeline, narrativeEntries, shapValues } from './mockAttackScenario';

export const scenarios = {
  'A_BRUTE_FORCE': {
    name: 'Scenario A: External Brute Force & Lateral Movement',
    hosts, attackProfile, initialNodes, initialEdges, urgencyTimeline, detections, infiltrationTimeline, narrativeEntries, shapValues
  },
  'B_EXFILTRATION': {
    name: 'Scenario B: Stealth Data Exfiltration (DNS Tunneling)',
    hosts: { ...hosts, attacker: { ...hosts.attacker, ip: '10.50.2.11 (Insider)', roles: ['Database Server'], attackRating: 9, velocity: 'Low' } },
    attackProfile: { classification: 'Insider Threat / Exfiltration', description: 'Large volume of DNS TXT records indicating tunneling.', positiveIndicators: ['DNS Tunneling', 'High outbound traffic'] },
    initialNodes: [
      { id: 'db1', data: { label: 'DB Cluster 1', isAttacker: true, icon: 'target' }, position: { x: 100, y: 100 } },
      { id: 'dns', data: { label: 'Ext DNS (8.8.8.8)', isAttacker: false, icon: 'attacker' }, position: { x: 400, y: 100 } }
    ],
    initialEdges: [
      { id: 'e1', source: 'db1', target: 'dns', label: 'DNS TXT (5GB)' }
    ],
    urgencyTimeline: urgencyTimeline.map(d => ({ ...d, value: Math.min(d.value + 20, 100) })),
    detections: [
      { id: 'd1', category: 'EXFILTRATION', categoryClass: 'critical', type: 'DNS Tunneling Detected', status: 'Active', statusClass: 'active', firstSeen: new Date(Date.now() - 3600000).toISOString(), lastSeen: new Date().toISOString() }
    ],
    infiltrationTimeline: infiltrationTimeline.map(d => ({ ...d, tactic: d.tactic.replace('Lateral Movement', 'Data Exfiltration') })),
    narrativeEntries: [
      { type: 'confirmed', timestamp: '10:05 AM', text: 'Database server db1 initiated 10k+ DNS TXT requests to 8.8.8.8.', evidence: 'DNS Query Log ID: 991' },
      { type: 'predicted', timestamp: '10:06 AM', text: 'Model predicts ongoing data exfiltration via DNS tunneling.', evidence: 'K-Step Rollout' }
    ],
    shapValues: [
      { feature: 'DNS_Req_Count', value: 0.85, direction: 'positive' },
      { feature: 'Avg_Packet_Size', value: 0.45, direction: 'positive' }
    ]
  },
  'C_INSIDER': {
    name: 'Scenario C: Insider Threat (Anomalous Access)',
    hosts: { ...hosts, attacker: { ...hosts.attacker, ip: 'Employee Workstation', roles: ['Finance User'], attackRating: 7, velocity: 'High' } },
    attackProfile: { classification: 'Insider Threat', description: 'Unusual access patterns to HR and Finance databases at 3 AM.', positiveIndicators: ['Off-hours access', 'Large DB query'] },
    initialNodes: [
      { id: 'user1', data: { label: 'Alice (Finance)', isAttacker: true, icon: 'attacker' }, position: { x: 100, y: 100 } },
      { id: 'hr_db', data: { label: 'HR Database', isAttacker: false, icon: 'target' }, position: { x: 400, y: 100 } }
    ],
    initialEdges: [
      { id: 'e1', source: 'user1', target: 'hr_db', label: 'SQL Query (SELECT *)' }
    ],
    urgencyTimeline: urgencyTimeline.map(d => ({ ...d, value: Math.max(d.value - 20, 10) })),
    detections: [
      { id: 'd1', category: 'ANOMALY', categoryClass: 'high', type: 'Off-hours DB Access', status: 'Active', statusClass: 'active', firstSeen: new Date(Date.now() - 3600000).toISOString(), lastSeen: new Date().toISOString() }
    ],
    infiltrationTimeline: infiltrationTimeline.map(d => ({ ...d, tactic: d.tactic.replace('Reconnaissance', 'Collection') })),
    narrativeEntries: [
      { type: 'confirmed', timestamp: '03:15 AM', text: 'User Alice accessed HR Database outside normal working hours.', evidence: 'Auth Log ID: 510' },
      { type: 'predicted', timestamp: '03:20 AM', text: 'Model predicts data staging for potential internal leak.', evidence: 'K-Step Rollout' }
    ],
    shapValues: [
      { feature: 'Hour_Of_Day', value: 0.95, direction: 'positive' },
      { feature: 'Bytes_Transferred', value: 0.55, direction: 'positive' }
    ]
  }
};
