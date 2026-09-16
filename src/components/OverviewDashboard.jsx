import { Target, Activity, ShieldAlert, Cpu, Network, Layers, Link2, TrendingUp, AlertTriangle, Bug, Anchor, Radio, Database, UploadCloud, Flame, Eraser, Search, LogIn, Key, Zap, User, Package } from 'lucide-react';

export default function OverviewDashboard({ data }) {
  const stats = data.overviewStats || data?.stats || {};
  
  const iconMap = {
    '🦠': <Bug size={16} strokeWidth={2.5} />,
    '⚓': <Anchor size={16} strokeWidth={2.5} />,
    '📡': <Radio size={16} strokeWidth={2.5} />,
    '🗂️': <Database size={16} strokeWidth={2.5} />,
    '📤': <UploadCloud size={16} strokeWidth={2.5} />,
    '💥': <Flame size={16} strokeWidth={2.5} />,
    '🧹': <Eraser size={16} strokeWidth={2.5} />,
    '🔍': <Search size={16} strokeWidth={2.5} />,
    '🚪': <LogIn size={16} strokeWidth={2.5} />,
    '🔑': <Key size={16} strokeWidth={2.5} />,
    '⚡': <Zap size={16} strokeWidth={2.5} />,
    '👤': <User size={16} strokeWidth={2.5} />,
    '📦': <Package size={16} strokeWidth={2.5} />,
  };
  const networkLogs = data.networkLogs || [];
  const mitreStages = data.mitreStages || [];

  const totalFlows = stats.totalFlows ?? 0;
  const maliciousFlows = stats.maliciousFlows ?? 0;
  const uniqueHosts = (data.hosts?.targets?.length ?? 0) + 1;
  const activeAlerts = stats.activeAlerts ?? 0;
  const worldModelConf = stats.worldModelConfidence ?? 0;
  const worldModelTrend = stats.worldModelTrend ?? '';

  return (
    <div style={{ display: 'flex', gap: 'var(--space-4)', height: '100%', width: '100%', flexWrap: 'wrap', alignItems: 'flex-start' }}>

      {/* ─── Left Column ─── */}
      <div style={{ flex: '1 1 300px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>

        {/* Threat Summary Stats */}
        <div
          className="overview-stats-grid"
          style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--space-3)', flexShrink: 0 }}
        >
          {[
            { label: 'Total Flows', value: totalFlows.toLocaleString(), color: 'var(--accent-primary)' },
            { label: 'Malicious Flows', value: maliciousFlows.toLocaleString(), color: 'var(--severity-critical)' },
            { label: 'Unique Hosts', value: uniqueHosts, color: 'var(--severity-high)' },
            { label: 'Active Alerts', value: activeAlerts, color: 'var(--severity-medium)' },
          ].map(item => (
            <div key={item.label} className="solid-panel" style={{ padding: 'var(--space-4)', textAlign: 'center', borderRadius: 'var(--radius-lg)' }}>
              <div style={{ fontSize: '1.6rem', fontWeight: 800, color: item.color, lineHeight: 1.1 }}>
                {item.value}
              </div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginTop: 4 }}>
                {item.label}
              </div>
            </div>
          ))}
        </div>

        {/* MITRE ATT&CK Kill Chain */}
        <div className="solid-panel" style={{ padding: 'var(--space-4) var(--space-6)', flexShrink: 0, borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-tertiary)', marginBottom: 'var(--space-4)' }}>
            MITRE ATT&CK Kill Chain Progression
          </div>
          <div className="mitre-chain-wrapper">
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '52px 24px 44px', minWidth: 560 }}>

              {/* Horizontal line */}
              <div style={{
                position: 'absolute', left: 24, right: 24, top: '50%', height: 3,
                background: 'var(--surface-border)',
                borderRadius: 2, transform: 'translateY(-50%)',
              }} />

              {mitreStages.map((stage, i) => {
                const isTop = i % 2 === 0;
                const colorMap = { confirmed: 'var(--severity-low)', current: 'var(--severity-medium)', predicted: 'var(--severity-critical)', inactive: 'var(--surface-border)' };
                const stageColor = colorMap[stage.status] || 'var(--surface-border)';

                return (
                  <div key={stage.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative', zIndex: 2, flex: 1 }}>

                    {isTop && (
                      <div style={{ position: 'absolute', bottom: 'calc(100% + 10px)', left: '50%', transform: 'translateX(-50%)', textAlign: 'center', width: 120 }}>
                        <div style={{ fontWeight: 700, fontSize: 10, color: stage.status === 'inactive' ? 'var(--text-tertiary)' : 'var(--text-primary)', lineHeight: 1.3 }}>
                          {stage.name}
                        </div>
                        <div style={{ fontSize: 9, color: 'var(--text-tertiary)', marginTop: 1 }}>{stage.desc}</div>
                        {stage.prob && (
                          <div style={{ fontSize: 9, fontWeight: 800, color: stageColor, marginTop: 1 }}>
                            P = {stage.prob}
                          </div>
                        )}
                      </div>
                    )}

                    <div style={{
                      width: 36, height: 36,
                      borderRadius: '50%',
                      background: stage.status === 'inactive' ? 'var(--bg-tertiary)'
                        : stage.status === 'predicted' ? 'var(--bg-secondary)'
                        : stageColor,
                      border: stage.status === 'predicted' ? `2.5px dashed ${stageColor}`
                        : `2.5px solid ${stageColor}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 16,
                      boxShadow: stage.status === 'current' ? `0 0 12px ${stageColor}50` : 'var(--shadow-sm)',
                      animation: stage.status === 'current' ? 'pulse 2s infinite' : undefined,
                    }}>
                      {iconMap[stage.icon] || stage.icon}
                    </div>

                    {!isTop && (
                      <div style={{ position: 'absolute', top: 'calc(100% + 10px)', left: '50%', transform: 'translateX(-50%)', textAlign: 'center', width: 120 }}>
                        <div style={{ fontWeight: 700, fontSize: 10, color: stage.status === 'inactive' ? 'var(--text-tertiary)' : 'var(--text-primary)', lineHeight: 1.3 }}>
                          {stage.name}
                        </div>
                        <div style={{ fontSize: 9, color: 'var(--text-tertiary)', marginTop: 1 }}>{stage.desc}</div>
                        {stage.prob && (
                          <div style={{ fontSize: 9, fontWeight: 800, color: stageColor, marginTop: 1 }}>
                            P = {stage.prob}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Recent Network Logs */}
        <div className="solid-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header" style={{ background: 'var(--bg-secondary)' }}>
            <span className="panel-title">
              <Activity size={13} />
              Recent Network Flows
            </span>
            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
              {networkLogs.length} entries · {stats.dataset || 'Dataset'}
            </span>
          </div>
          <div style={{ flex: 1, overflow: 'auto', maxHeight: '35vh' }} className="table-scroll-wrapper">
            <table className="data-table" style={{ fontSize: '11px' }}>
              <thead>
                <tr>
                  {['Time', 'Source', 'Destination', 'Proto', 'Port', 'Flags', 'Bytes', 'Label'].map(h => (
                    <th key={h} style={{ position: 'sticky', top: 0, background: 'var(--bg-secondary)', zIndex: 1 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {networkLogs.map(log => (
                  <tr key={log.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', fontSize: 10 }}>{log.ts}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>{log.src}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>{log.dst}</td>
                    <td>{log.proto}</td>
                    <td>{log.port || '—'}</td>
                    <td><span style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>{log.flags}</span></td>
                    <td style={{ whiteSpace: 'nowrap' }}>{log.bytes.toLocaleString()}</td>
                    <td>
                      <span className={`badge badge-${log.severity}`}>{log.label}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* ─── Right Column ─── */}
      <div className="overview-right-col" style={{ width: 320, flex: '0 0 320px', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)', flexShrink: 0 }}>

        {/* Dataset Overview */}
        <div className="solid-panel" style={{ padding: 'var(--space-4)', flexShrink: 0, borderRadius: 'var(--radius-lg)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-tertiary)', marginBottom: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Database size={11} /> Active Dataset
          </div>
          <div style={{ background: 'var(--accent-light)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
            <div style={{ fontWeight: 800, fontSize: 'var(--text-lg)', color: 'var(--accent-primary)' }}>{stats.dataset || 'N/A'}</div>
            <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{stats.subset || ''}</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
            {[
              { label: 'Rows', value: stats.rows },
              { label: 'Features', value: stats.features },
              { label: 'Window', value: stats.duration },
              { label: 'Attack Types', value: (stats.attackTypes || []).length },
            ].map(item => (
              <div key={item.label} style={{ padding: 'var(--space-2) var(--space-3)', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-sm)' }}>
                <div style={{ fontSize: 9, color: 'var(--text-tertiary)', fontWeight: 600, textTransform: 'uppercase' }}>{item.label}</div>
                <div style={{ fontWeight: 700, fontSize: 'var(--text-sm)' }}>{item.value ?? 'N/A'}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 'var(--space-3)', display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            {(stats.attackTypes || []).map(t => (
              <span key={t} className="badge badge-critical">{t}</span>
            ))}
          </div>
        </div>

        {/* World Model Confidence */}
        <div className="solid-panel" style={{ padding: 'var(--space-4)', flexShrink: 0, borderRadius: 'var(--radius-lg)' }}>
          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text-tertiary)', marginBottom: 'var(--space-3)' }}>
            World Model Confidence
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <div style={{
              width: 58, height: 58, flexShrink: 0,
              borderRadius: 'var(--radius-full)',
              border: `4px solid ${worldModelConf >= 80 ? 'var(--severity-critical)' : worldModelConf >= 60 ? 'var(--severity-high)' : 'var(--severity-medium)'}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: 800, fontSize: 15,
              color: worldModelConf >= 80 ? 'var(--severity-critical)' : worldModelConf >= 60 ? 'var(--severity-high)' : 'var(--severity-medium)',
            }}>
              {worldModelConf}%
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 700, fontSize: 'var(--text-sm)' }}>Infiltration Probability</div>
              <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>K=3 step forward simulation</div>
              <div style={{ fontSize: 11, color: 'var(--severity-critical)', fontWeight: 600, marginTop: 2, lineHeight: 1.4 }}>
                <TrendingUp size={11} style={{ marginRight: 2, verticalAlign: 'middle' }} />
                {worldModelTrend}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
