import { Paperclip, Terminal, FileText, FastForward } from 'lucide-react';

export default function AttackStoryReconstruction({ data }) {
  const narrative = data.narrativeEntries || [];

  return (
    <div style={{ display: 'flex', height: '100%', gap: 'var(--space-6)', padding: 'var(--space-4)' }}>
      {/* Left Pane: Raw Logs */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: '#0f172a', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
        <div style={{ padding: 'var(--space-3)', borderBottom: '1px solid #1e293b', display: 'flex', alignItems: 'center', gap: '8px', color: '#94a3b8' }}>
          <Terminal size={16} />
          <span style={{ fontSize: '12px', fontWeight: 600 }}>Raw Log Stream (SIEM/EDR)</span>
          <FastForward size={14} style={{ marginLeft: 'auto', color: 'var(--severity-low)' }} />
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: 'var(--space-4)', fontFamily: 'var(--font-mono)', fontSize: '10px', color: '#cbd5e1', lineHeight: 1.6 }}>
          <div style={{ color: '#3b82f6' }}>[09:59:12] SYSTEM: Initiating Correlation Engine...</div>
          <div style={{ color: '#3b82f6' }}>[09:59:13] SYSTEM: Awaiting World Model Focus Signal...</div>
          <div style={{ marginTop: '12px' }}>[10:01:05] [NETFLOW] src=10.254.50.107 dst=10.200.1.50 port=445 proto=TCP flags=S bytes=64</div>
          <div>[10:01:06] [NETFLOW] src=10.254.50.107 dst=10.200.1.51 port=445 proto=TCP flags=S bytes=64</div>
          <div style={{ color: '#eab308' }}>[10:01:08] [IDS] alert: possible RPC scanning from 10.254.50.107</div>
          <div style={{ color: '#ef4444', marginTop: '12px' }}>[10:03:00] [SYSTEM] WORLD MODEL SIGNAL RECEIVED: Predict Attack Stage=Reconnaissance, P=0.85</div>
          <div style={{ color: '#3b82f6' }}>[10:03:01] [CORRELATION] Triggering localized graph extraction around IP 10.254.50.107 (Window -5m to +1m)</div>
          <div style={{ marginTop: '12px' }}>[10:05:40] [WIN_EVT] EventID=4624 LogonType=3 user=svc_backup src=10.254.50.107 status=Success</div>
          <div style={{ color: '#eab308' }}>[10:05:45] [EDR] alert: psexec.exe executed on 10.200.1.50 (parent: services.exe)</div>
          <div style={{ color: '#ef4444', marginTop: '12px' }}>[10:08:10] [SYSTEM] WORLD MODEL SIGNAL RECEIVED: Predict Attack Stage=Lateral Movement, P=0.92</div>
          <div style={{ color: '#3b82f6' }}>[10:08:11] [CORRELATION] Correlating EDR alert with Auth Log ID 4624 -&gt; Graph edge formed.</div>
          <div style={{ color: '#10b981', marginTop: '12px', fontWeight: 700 }}>[10:08:15] [FUSION] Evidence confirms prediction. Boosting probability. Generating Narrative...</div>
        </div>
      </div>

      {/* Right Pane: Story Reconstruction */}
      <div style={{ flex: 1.5, display: 'flex', flexDirection: 'column', background: 'var(--bg-secondary)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--surface-border)' }}>
        <div style={{ padding: 'var(--space-3)', borderBottom: '1px solid var(--surface-border)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FileText size={16} color="var(--accent-primary)" />
          <span style={{ fontSize: '12px', fontWeight: 600 }}>Grounded Attack Story (LLM Output)</span>
        </div>
        <div style={{ flex: 1, padding: 'var(--space-6)', overflowY: 'auto' }}>
          
          <div style={{ background: 'var(--accent-light)', padding: 'var(--space-4)', borderRadius: 'var(--radius-md)', marginBottom: 'var(--space-6)', borderLeft: '4px solid var(--accent-primary)' }}>
            <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--accent-primary)', marginBottom: '4px', textTransform: 'uppercase' }}>Methodology</h4>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              This narrative is generated automatically by a local language model. 
              <strong> Crucially, every claim marked [CONFIRMED] must be grounded by a specific log citation</strong> extracted by the correlation graph, preventing hallucinations.
            </p>
          </div>

          {narrative.map((entry, i) => (
            <div key={i} className={`narrative-entry ${entry.type}`}>
              <div className={`narrative-tag ${entry.type}`}>
                {entry.type === 'confirmed' ? '✓ CONFIRMED' :
                 entry.type === 'predicted' ? '⚡ PREDICTED' : '🎯 ACTION'}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                {entry.timestamp}
              </div>
              <div className="narrative-text">{entry.text}</div>
              {entry.evidence && (
                <div className="narrative-evidence">
                  <Paperclip size={12} style={{ flexShrink: 0 }} />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.evidence}</span>
                </div>
              )}
            </div>
          ))}

        </div>
      </div>
    </div>
  );
}
