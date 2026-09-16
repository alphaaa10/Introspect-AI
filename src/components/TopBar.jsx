import { useState, useContext } from 'react';
import { WifiOff, Search, ShieldAlert, Sun, Moon } from 'lucide-react';
import { ScenarioContext } from '../App';

export default function TopBar({ data }) {
  const { currentScenarioKey, setCurrentScenarioKey, scenarios, goHome, theme, toggleTheme } = useContext(ScenarioContext);
  const [showOfflineToast, setShowOfflineToast] = useState(false);

  const host = data.hosts?.attacker;

  const handleSearchClick = () => {
    setShowOfflineToast(true);
    setTimeout(() => setShowOfflineToast(false), 3000);
  };

  return (
    <>
      {/* Offline Search Toast */}
      {showOfflineToast && (
        <div className="offline-toast">
          <Search size={14} />
          Search is unavailable in offline / simulation view
        </div>
      )}

      <div style={{ minWidth: 0, flex: 1 }}>
        <h1 className="topbar-title">Active Investigation</h1>
        <div className="topbar-subtitle">
          <select
            value={currentScenarioKey || ''}
            onChange={(e) => {
              if (e.target.value === '') {
                goHome();
              } else {
                setCurrentScenarioKey(e.target.value);
              }
            }}
            style={{
              background: 'var(--accent-light)',
              border: '1px solid rgba(37, 99, 235, 0.2)',
              borderRadius: 'var(--radius-sm)',
              padding: '2px 6px',
              fontSize: '11px',
              fontWeight: 600,
              color: 'var(--accent-primary)',
              cursor: 'pointer',
              maxWidth: '100%',
            }}
          >
            <option value="">← Back to Dataset Selection</option>
            {Object.entries(scenarios).map(([key, scenario]) => (
              <option key={key} value={key}>{scenario.name}</option>
            ))}
          </select>
          <span style={{ color: 'var(--surface-border)' }}>|</span>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            Host:{' '}
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
              {host?.ip || 'N/A'}
            </span>
          </span>
        </div>
      </div>

      <div className="topbar-actions">
        {/* Risk Score + Status Pill */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'row',
            alignItems: 'center',
            padding: '4px 12px',
            gap: '12px',
            borderRadius: 'var(--radius-sm)',
            background: 'var(--accent-light)',
            border: '1px solid rgba(37, 99, 235, 0.2)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', borderRight: '1px solid rgba(37, 99, 235, 0.2)', paddingRight: '12px' }}>
            <span style={{ fontSize: '10px', color: 'var(--accent-primary)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.5px', opacity: 0.8 }}>
              Risk Score
            </span>
            <span style={{ color: 'var(--severity-critical)', fontWeight: 800, fontSize: '15px' }}>
              {host?.urgencyScore ?? 100}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '10px', color: 'var(--accent-primary)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.5px', opacity: 0.8 }}>
              Status
            </span>
            <span style={{ color: 'var(--severity-critical)', fontSize: '11px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '4px' }}>
              <ShieldAlert size={13} />
              {host?.priorityStatus || 'PRIORITIZED'}
            </span>
          </div>
        </div>

        {/* Theme Toggle */}
        <button
          className="icon-btn"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
        >
          {theme === 'light' ? <Moon size={20} /> : <Sun size={20} />}
        </button>

        {/* Search — offline only */}
        <button
          className="icon-btn desktop-search-btn"
          onClick={handleSearchClick}
          title="Search (offline view)"
        >
          <Search size={17} />
        </button>
      </div>
    </>
  );
}
