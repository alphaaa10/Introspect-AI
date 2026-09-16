import { useContext } from 'react';
import { Bell, Search, ShieldAlert, ChevronDown } from 'lucide-react';
import { ScenarioContext } from '../App';

export default function TopBar({ data }) {
  const { currentScenarioKey, setCurrentScenarioKey, scenarios } = useContext(ScenarioContext);
  const host = data.hosts.attacker;

  return (
    <>
      <div>
        <h1 className="topbar-title">Active Investigation</h1>
        <div className="topbar-subtitle" style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
          <select 
            value={currentScenarioKey}
            onChange={(e) => setCurrentScenarioKey(e.target.value)}
            style={{ 
              background: 'var(--bg-secondary)', 
              border: '1px solid var(--surface-border)', 
              borderRadius: 'var(--radius-sm)', 
              padding: '2px 8px', 
              fontSize: '11px', 
              fontWeight: 600,
              color: 'var(--accent-primary)',
              cursor: 'pointer'
            }}
          >
            {Object.entries(scenarios).map(([key, scenario]) => (
              <option key={key} value={key}>{scenario.name}</option>
            ))}
          </select>
          <span style={{ color: 'var(--surface-border)' }}>|</span>
          <span>Analyzing Host: <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{host.ip}</span></span>
        </div>
      </div>

      <div className="topbar-actions">
        <div className="glass-panel" style={{ flexDirection: 'row', alignItems: 'center', padding: '6px 16px', gap: '12px', borderRadius: 'var(--radius-full)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', borderRight: '1px solid rgba(0,0,0,0.1)', paddingRight: '12px' }}>
            <span style={{ fontSize: '10px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Risk Score</span>
            <span style={{ color: 'var(--severity-critical)', fontWeight: 800 }}>{host.urgencyScore || 100}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '10px', color: 'var(--text-tertiary)', textTransform: 'uppercase', fontWeight: 700 }}>Status</span>
            <span style={{ color: 'var(--severity-critical)', fontSize: '12px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
              <ShieldAlert size={14} /> PRIORITIZED
            </span>
          </div>
        </div>

        <button className="icon-btn">
          <Search size={18} />
        </button>
        <button className="icon-btn" style={{ position: 'relative' }}>
          <Bell size={18} />
          <span style={{ position: 'absolute', top: 8, right: 10, width: 6, height: 6, borderRadius: '50%', background: 'var(--severity-critical)' }} />
        </button>
      </div>
    </>
  );
}
