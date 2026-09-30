import { useState, useRef } from 'react';
import { LogoIcon } from './Icons';
import { UploadCloud, Database, Server, Network, UserX,
         CheckCircle2, AlertTriangle, Loader2, FileUp } from 'lucide-react';
import { analyzeLogs } from '../api/client';

export default function SetupScreen({ onComplete, initialMode = null }) {
  const [mode, setMode] = useState(initialMode);
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [coverage, setCoverage] = useState(null); // report on refusal or success
  const fileInputRef = useRef(null);

  const handleDatasetSelect = (datasetKey) => {
    onComplete(datasetKey);
  };

  const handleUploadComplete = async () => {
    if (!file) { setError('Choose a flow-log CSV first.'); return; }
    setLoading(true); setError(null); setCoverage(null);
    const res = await analyzeLogs(file);
    setLoading(false);
    if (res.ok) {
      onComplete('upload', res.data);          // hand the analyzed scenario to App
    } else {
      setError(res.error);
      if (res.coverage) setCoverage(res.coverage); // 422: show what's missing
    }
  };

  if (mode === 'upload') {
    const isRefusal = coverage && coverage.ok === false;
    return (
      <div className="setup-container">
        <div className="setup-logo" style={{ marginBottom: 'var(--space-6)' }}>
          <div className="setup-logo-icon" style={{ width: 48, height: 48 }}>
            <LogoIcon size={24} />
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>Upload Flow Logs</h2>
          <p style={{ color: 'var(--text-secondary)' }}>
            CIC-IDS-2017 / CICFlowMeter CSV. The world model + LightGBM stage classifier run on your file.
          </p>
        </div>

        <div className="solid-panel" style={{ width: '100%', maxWidth: 600, padding: 'var(--space-6)' }}>
          <input
            ref={fileInputRef} type="file" accept=".csv,text/csv" style={{ display: 'none' }}
            onChange={(e) => { setFile(e.target.files?.[0] || null); setError(null); setCoverage(null); }}
          />

          <div
            className="dropzone"
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f) { setFile(f); setError(null); setCoverage(null); } }}
            style={{ cursor: 'pointer' }}
          >
            {file
              ? <CheckCircle2 size={32} color="var(--accent-primary)" style={{ marginBottom: 12 }} />
              : <FileUp size={32} color="var(--accent-primary)" style={{ marginBottom: 12 }} />}
            <h4 style={{ fontWeight: 600, marginBottom: 4 }}>
              {file ? file.name : 'Flow Logs (CSV) — Required'}
            </h4>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>
              {file ? `${(file.size / 1024 / 1024).toFixed(1)} MB — click to change`
                    : 'Click to browse or drop a CICFlowMeter/CIC-IDS-2017 flow CSV'}
            </p>
          </div>

          {/* Error / refusal */}
          {error && (
            <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                          background: 'color-mix(in srgb, var(--severity-critical) 12%, transparent)',
                          border: '1px solid var(--severity-critical)', display: 'flex', gap: 8, alignItems: 'flex-start' }}>
              <AlertTriangle size={16} color="var(--severity-critical)" style={{ flexShrink: 0, marginTop: 2 }} />
              <div style={{ fontSize: 'var(--text-sm)' }}>
                <div style={{ fontWeight: 600 }}>{isRefusal ? 'Insufficient feature coverage' : 'Analysis failed'}</div>
                <div style={{ color: 'var(--text-secondary)' }}>{error}</div>
                {isRefusal && coverage?.missing?.length > 0 && (
                  <ul style={{ margin: '6px 0 0 16px', color: 'var(--text-secondary)' }}>
                    {coverage.missing.slice(0, 8).map((m) => <li key={m}>{m}</li>)}
                  </ul>
                )}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 'var(--space-4)', marginTop: 'var(--space-4)' }}>
            <button
              onClick={() => { setMode(null); setFile(null); setError(null); setCoverage(null); }}
              disabled={loading}
              style={{ flex: 1, padding: 'var(--space-3)', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)', fontWeight: 600 }}
            >
              Back
            </button>
            <button
              onClick={handleUploadComplete}
              disabled={loading || !file}
              className="primary-btn"
              style={{ flex: 2, margin: 0, opacity: (loading || !file) ? 0.6 : 1,
                       display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
            >
              {loading ? <><Loader2 size={16} className="spin" /> Analyzing…</> : 'Process Logs & Launch'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (mode === 'select-dataset') {
    return (
      <div className="setup-container">
        <div className="setup-logo" style={{ marginBottom: 'var(--space-6)' }}>
          <div className="setup-logo-icon" style={{ width: 48, height: 48 }}>
            <LogoIcon size={24} />
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>Select Pre-analyzed Dataset</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Choose a realistic offline simulation to launch</p>
        </div>

        <div className="setup-cards" style={{ maxWidth: 1000 }}>
          <div className="solid-panel setup-card" onClick={() => handleDatasetSelect('A_BRUTE_FORCE')}>
            <div className="setup-card-icon">
              <Server size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem' }}>CIC-IDS-2018</h3>
            <div style={{ color: 'var(--accent-primary)', fontWeight: 600, fontSize: '0.85rem', marginBottom: '8px' }}>Enterprise Infiltration</div>
            <p style={{ fontSize: '0.85rem' }}>Classic kill chain progression: SSH Brute Force leading to Lateral Movement and internal DB access.</p>
            <button className="primary-btn">Launch Simulation</button>
          </div>

          <div className="solid-panel setup-card" onClick={() => handleDatasetSelect('B_EXFILTRATION')}>
            <div className="setup-card-icon" style={{ color: 'var(--severity-high)' }}>
              <Network size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem' }}>CTU-13</h3>
            <div style={{ color: 'var(--severity-high)', fontWeight: 600, fontSize: '0.85rem', marginBottom: '8px' }}>Botnet C2 Campaign</div>
            <p style={{ fontSize: '0.85rem' }}>Features stealthy C&C communication and large volume DNS exfiltration behaviors.</p>
            <button className="primary-btn" style={{ background: 'var(--severity-high)' }}>Launch Simulation</button>
          </div>

          <div className="solid-panel setup-card" onClick={() => handleDatasetSelect('C_INSIDER')}>
            <div className="setup-card-icon" style={{ color: 'var(--severity-medium)' }}>
              <UserX size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem' }}>UNSW-NB15</h3>
            <div style={{ color: 'var(--severity-medium)', fontWeight: 600, fontSize: '0.85rem', marginBottom: '8px' }}>Insider Threat</div>
            <p style={{ fontSize: '0.85rem' }}>Focuses on anomalous off-hours database access and unauthorized data collection by an employee.</p>
            <button className="primary-btn" style={{ background: 'var(--severity-medium)' }}>Launch Simulation</button>
          </div>
        </div>

        <button 
          onClick={() => setMode(null)}
          style={{ padding: 'var(--space-3) var(--space-6)', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)', fontWeight: 600, marginTop: 'var(--space-6)' }}
        >
          Back
        </button>
      </div>
    );
  }

  return (
    <div className="setup-container">
      <div className="setup-logo">
        <div className="setup-logo-icon">
          <LogoIcon />
        </div>
        <div className="setup-logo-text">Introspect AI</div>
        <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-lg)', marginTop: '-8px' }}>
          Predictive Cyber Defense System
        </p>
      </div>

      <div className="setup-cards">
        <div className="solid-panel setup-card" onClick={() => setMode('select-dataset')}>
          <div className="setup-card-icon">
            <Database size={24} />
          </div>
          <h3>Start SIH Simulation</h3>
          <p>Launch the dashboard with a pre-configured, realistic attack scenario spanning 15 minutes of network traffic.</p>
          <button className="primary-btn">Select Dataset</button>
        </div>

        <div className="solid-panel setup-card" onClick={() => setMode('upload')}>
          <div className="setup-card-icon">
            <UploadCloud size={24} />
          </div>
          <h3>Upload Custom Logs</h3>
          <p>Run the correlation engine and world model against your own enterprise security logs (CSV/JSON).</p>
          <button className="primary-btn" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', boxShadow: 'none' }}>
            Upload Files
          </button>
        </div>
      </div>
    </div>
  );
}
