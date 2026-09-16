import { useState } from 'react';
import { Activity, Database, Cpu, Shield, Clock, AlertTriangle, ChevronDown, ChevronUp, Zap, TrendingUp, Server, Network } from 'lucide-react';

// Generate 25 realistic CIC-IDS-2018 style network logs
function generateLogs() {
  return [
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
  ];
}

export default function OverviewDashboard({ data }) {
  const logs = generateLogs();
  
  const totalFlows = 14893;
  const maliciousFlows = 2847;
  const uniqueHosts = (data.hosts?.targets?.length || 9) + 1;
  const criticalAlerts = data.detections?.filter(d => d.categoryClass === 'cc' || d.categoryClass === 'lateral').length || 4;

  const currentDataset = { name: 'CIC-IDS-2018', subset: 'Thursday-WorkingHours (SSH-Bruteforce)', rows: '14,893 flows', features: 78, duration: '15 min window', attackTypes: ['SSH-Bruteforce', 'Infiltration'] };

  const pipelineSteps = [
    { icon: Database, name: 'Ingestion', desc: 'Raw CSV/PCAP parsing', status: 'complete', metric: `${currentDataset.rows} ingested` },
    { icon: Cpu, name: 'Feature Extraction', desc: `${currentDataset.features} CIC flow features`, status: 'complete', metric: '78 features/flow' },
    { icon: Network, name: 'Graph Construction', desc: '60s temporal windows', status: 'complete', metric: `${uniqueHosts} nodes, 14 edges` },
    { icon: Zap, name: 'World Model', desc: 'GCN + LSTM forward pass', status: 'active', metric: 'K=3 step rollout' },
    { icon: Shield, name: 'Threat Scoring', desc: 'MITRE ATT&CK mapping', status: 'pending', metric: 'P(infiltration) = 0.82' },
  ];

  return (
    <div style={{ display: 'flex', gap: 'var(--space-6)', height: '100%', width: '100%' }}>
      {/* Left Column - Stats + MITRE + Logs */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 'var(--space-6)', minWidth: 0 }}>
        
        {/* Threat Summary Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--space-4)', flexShrink: 0 }}>
          <div className="glass-panel" style={{ padding: 'var(--space-4)', textAlign: 'center', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--accent-primary)' }}>{totalFlows.toLocaleString()}</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Total Flows</div>
          </div>
          <div className="glass-panel" style={{ padding: 'var(--space-4)', textAlign: 'center', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--severity-critical)' }}>{maliciousFlows.toLocaleString()}</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Malicious Flows</div>
          </div>
          <div className="glass-panel" style={{ padding: 'var(--space-4)', textAlign: 'center', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--severity-high)' }}>{uniqueHosts}</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Unique Hosts</div>
          </div>
          <div className="glass-panel" style={{ padding: 'var(--space-4)', textAlign: 'center', borderRadius: 'var(--radius-lg)' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: 'var(--severity-medium)' }}>{criticalAlerts}</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Active Alerts</div>
          </div>
        </div>

        {/* MITRE ATT&CK Timeline Infographic */}
        <div className="glass-panel" style={{ padding: 'var(--space-4) var(--space-6)', flexShrink: 0, borderRadius: 'var(--radius-lg)' }}>
          <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-tertiary)', marginBottom: 'var(--space-4)' }}>
            MITRE ATT&CK Kill Chain Progression
          </div>
          
          {/* Timeline */}
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '48px 0' }}>
            {/* Horizontal line */}
            <div style={{ position: 'absolute', left: 20, right: 20, top: '50%', height: 3, background: 'linear-gradient(90deg, var(--severity-low), var(--severity-low) 42%, var(--severity-medium) 42%, var(--severity-medium) 57%, var(--severity-critical) 57%, var(--severity-critical) 72%, var(--surface-border) 72%)', borderRadius: 2, transform: 'translateY(-50%)' }} />
            
            {[
              { id: 'RECON', name: 'Reconnaissance', icon: '🔍', status: 'confirmed', color: 'var(--severity-low)', desc: 'Port scanning detected', position: 'top' },
              { id: 'INIT', name: 'Initial Access', icon: '🚪', status: 'confirmed', color: 'var(--severity-low)', desc: 'SSH brute force (850 SYN)', position: 'bottom' },
              { id: 'CRED', name: 'Credential Access', icon: '🔑', status: 'confirmed', color: 'var(--severity-low)', desc: 'Auth success after 47 fails', position: 'top' },
              { id: 'LATERAL', name: 'Lateral Movement', icon: '⚡', status: 'current', color: 'var(--severity-medium)', desc: 'SMB to FILE-SVR-01', prob: '82%', position: 'bottom' },
              { id: 'C2', name: 'Command & Control', icon: '📡', status: 'predicted', color: 'var(--severity-critical)', desc: 'HTTP tunnel predicted', prob: '87%', position: 'top' },
              { id: 'EXFIL', name: 'Exfiltration', icon: '📤', status: 'predicted', color: 'var(--severity-critical)', desc: 'Data staging likely', prob: '91%', position: 'bottom' },
              { id: 'IMPACT', name: 'Impact', icon: '💥', status: 'inactive', color: 'var(--surface-border)', desc: 'Not yet predicted', position: 'top' },
            ].map((stage, i) => (
              <div key={stage.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative', zIndex: 2, flex: 1 }}>
                
                {/* Top label (for 'top' position stages) */}
                {stage.position === 'top' && (
                  <div style={{ position: 'absolute', bottom: 'calc(100% + 8px)', textAlign: 'center', width: 110 }}>
                    <div style={{ fontWeight: 700, fontSize: '10px', color: stage.status === 'inactive' ? 'var(--text-tertiary)' : 'var(--text-primary)' }}>{stage.name}</div>
                    <div style={{ fontSize: '9px', color: 'var(--text-tertiary)', marginTop: 1 }}>{stage.desc}</div>
                    {stage.prob && <div style={{ fontSize: '9px', fontWeight: 800, color: stage.color, marginTop: 1 }}>P = {stage.prob}</div>}
                  </div>
                )}

                {/* Circle node */}
                <div style={{
                  width: 36, height: 36,
                  borderRadius: '50%',
                  background: stage.status === 'inactive' ? 'var(--bg-tertiary)' : stage.status === 'predicted' ? 'white' : stage.color,
                  border: stage.status === 'predicted' ? `3px dashed ${stage.color}` : stage.status === 'current' ? `3px solid ${stage.color}` : `3px solid ${stage.color}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '16px',
                  boxShadow: stage.status === 'current' ? `0 0 12px ${stage.color}40` : 'var(--shadow-sm)',
                  color: (stage.status === 'confirmed') ? 'white' : undefined,
                  transition: 'all 0.3s ease',
                  animation: stage.status === 'current' ? 'pulse 2s infinite' : undefined,
                }}>
                  {stage.icon}
                </div>

                {/* Bottom label (for 'bottom' position stages) */}
                {stage.position === 'bottom' && (
                  <div style={{ position: 'absolute', top: 'calc(100% + 8px)', textAlign: 'center', width: 110 }}>
                    <div style={{ fontWeight: 700, fontSize: '10px', color: stage.status === 'inactive' ? 'var(--text-tertiary)' : 'var(--text-primary)' }}>{stage.name}</div>
                    <div style={{ fontSize: '9px', color: 'var(--text-tertiary)', marginTop: 1 }}>{stage.desc}</div>
                    {stage.prob && <div style={{ fontSize: '9px', fontWeight: 800, color: stage.color, marginTop: 1 }}>P = {stage.prob}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Recent Network Logs */}
        <div className="glass-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header" style={{ background: 'transparent', borderBottom: '1px solid rgba(226, 232, 240, 0.5)', flexShrink: 0 }}>
            <span className="panel-title">
              <Activity size={14} style={{ marginRight: 4 }} />
              Recent Network Flows
            </span>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>{logs.length} entries</span>
          </div>
          <div style={{ flex: 1, overflow: 'auto' }}>
            <table className="data-table" style={{ fontSize: '11px' }}>
              <thead>
                <tr>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Time</th>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Source</th>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Destination</th>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Proto</th>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Port</th>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Flags</th>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Bytes</th>
                  <th style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>Label</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>{log.ts}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{log.src}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{log.dst}</td>
                    <td>{log.proto}</td>
                    <td>{log.port}</td>
                    <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px' }}>{log.flags}</span></td>
                    <td>{log.bytes.toLocaleString()}</td>
                    <td>
                      <span className={`badge badge-${log.severity}`}>
                        {log.label}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Right Column - Dataset + Processing + Confidence */}
      <div style={{ width: 340, display: 'flex', flexDirection: 'column', gap: 'var(--space-6)', flexShrink: 0 }}>
        
        {/* Dataset Overview */}
        <div className="glass-panel" style={{ padding: 'var(--space-4)', flexShrink: 0, borderRadius: 'var(--radius-lg)' }}>
          <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-tertiary)', marginBottom: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Database size={12} /> Active Dataset
          </div>
          <div style={{ background: 'var(--accent-light)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
            <div style={{ fontWeight: 800, fontSize: 'var(--text-lg)', color: 'var(--accent-primary)' }}>{currentDataset.name}</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{currentDataset.subset}</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
            {[
              { label: 'Rows', value: currentDataset.rows },
              { label: 'Features', value: currentDataset.features },
              { label: 'Window', value: currentDataset.duration },
              { label: 'Attack Types', value: currentDataset.attackTypes.length },
            ].map(item => (
              <div key={item.label} style={{ padding: 'var(--space-2)', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: '10px', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase' }}>{item.label}</div>
                <div style={{ fontWeight: 700, fontSize: 'var(--text-sm)' }}>{item.value}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 'var(--space-3)', display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            {currentDataset.attackTypes.map(t => (
              <span key={t} className="badge badge-critical">{t}</span>
            ))}
          </div>
        </div>

        {/* Processing Pipeline */}
        <div className="glass-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRadius: 'var(--radius-lg)' }}>
          <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-tertiary)', padding: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Cpu size={12} /> Processing Pipeline
          </div>
          <div style={{ flex: 1, overflow: 'auto', padding: '0 var(--space-4) var(--space-4)' }}>
            {pipelineSteps.map((step, i) => (
              <div key={step.name} style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-4)', position: 'relative' }}>
                {i < pipelineSteps.length - 1 && (
                  <div style={{ position: 'absolute', left: 15, top: 32, width: 2, height: 'calc(100% + 4px)', background: step.status === 'complete' ? 'var(--severity-low)' : 'var(--surface-border)' }} />
                )}
                <div style={{
                  width: 32, height: 32, borderRadius: 'var(--radius-full)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  background: step.status === 'complete' ? 'rgba(16, 185, 129, 0.1)' : step.status === 'active' ? 'rgba(37, 99, 235, 0.1)' : 'var(--bg-tertiary)',
                  color: step.status === 'complete' ? 'var(--severity-low)' : step.status === 'active' ? 'var(--accent-primary)' : 'var(--text-tertiary)',
                  border: step.status === 'active' ? '2px solid var(--accent-primary)' : '1px solid var(--surface-border)',
                  zIndex: 1,
                }}>
                  <step.icon size={14} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 700, fontSize: 'var(--text-sm)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    {step.name}
                    {step.status === 'active' && <span style={{ fontSize: '9px', fontWeight: 800, background: 'rgba(37, 99, 235, 0.1)', color: 'var(--accent-primary)', padding: '1px 6px', borderRadius: 'var(--radius-full)' }}>RUNNING</span>}
                    {step.status === 'complete' && <span style={{ fontSize: '9px', fontWeight: 800, background: 'rgba(16, 185, 129, 0.1)', color: 'var(--severity-low)', padding: '1px 6px', borderRadius: 'var(--radius-full)' }}>✓ DONE</span>}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>{step.desc}</div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginTop: 2 }}>{step.metric}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* World Model Confidence */}
        <div className="glass-panel" style={{ padding: 'var(--space-4)', flexShrink: 0, borderRadius: 'var(--radius-lg)' }}>
          <div style={{ fontSize: 'var(--text-xs)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-tertiary)', marginBottom: 'var(--space-3)' }}>
            World Model Confidence
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <div style={{ width: 56, height: 56, borderRadius: 'var(--radius-full)', border: '4px solid var(--severity-critical)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: 'var(--text-lg)', color: 'var(--severity-critical)', flexShrink: 0 }}>
              82%
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 'var(--text-sm)' }}>Infiltration Probability</div>
              <div style={{ fontSize: '11px', color: 'var(--text-tertiary)' }}>K=3 step forward simulation</div>
              <div style={{ fontSize: '11px', color: 'var(--severity-critical)', fontWeight: 600, marginTop: 2 }}>
                <TrendingUp size={11} style={{ marginRight: 2, verticalAlign: 'middle' }} />
                Rising — predicted to reach 94% in 3 windows
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
