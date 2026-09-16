import { useState, useEffect } from 'react';
import { LogoIcon } from './Icons';
import { UploadCloud, Database, ShieldAlert, FileText, Share2, Server, Network, UserX } from 'lucide-react';

export default function SetupScreen({ onComplete, initialMode = null }) {
  const [mode, setMode] = useState(initialMode);
  const [showOfflineToast, setShowOfflineToast] = useState(false);

  useEffect(() => {
    if (mode === 'upload') {
      setShowOfflineToast(true);
      const timer = setTimeout(() => setShowOfflineToast(false), 4000);
      return () => clearTimeout(timer);
    }
  }, [mode]);

  const handleDatasetSelect = (datasetKey) => {
    onComplete(datasetKey);
  };

  const handleUploadComplete = () => {
    onComplete('upload');
  };

  if (mode === 'upload') {
    return (
      <div className="setup-container">
        {showOfflineToast && (
          <div className="offline-toast" style={{ top: 20, position: 'absolute' }}>
            <ShieldAlert size={14} />
            This feature is unavailable in offline / simulation mode
          </div>
        )}
        <div className="setup-logo" style={{ marginBottom: 'var(--space-6)' }}>
          <div className="setup-logo-icon" style={{ width: 48, height: 48 }}>
            <LogoIcon size={24} />
          </div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>Upload Enterprise Logs</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Provide CSV or JSON logs for the correlation engine</p>
        </div>

        <div className="solid-panel" style={{ width: '100%', maxWidth: 600, padding: 'var(--space-6)' }}>
          
          <div className="dropzone">
            <ShieldAlert size={32} color="var(--severity-critical)" style={{ marginBottom: 12 }} />
            <h4 style={{ fontWeight: 600, marginBottom: 4 }}>1. Attack Logs (Required)</h4>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>IDS alerts, firewall blocks, or EDR detections</p>
            <button className="primary-btn" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', boxShadow: 'none' }}>
              Browse Files
            </button>
          </div>

          <div className="dropzone">
            <Share2 size={32} color="var(--accent-primary)" style={{ marginBottom: 12 }} />
            <h4 style={{ fontWeight: 600, marginBottom: 4 }}>2. Relation Logs (Required)</h4>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>NetFlow, IPFIX, or proxy logs mapping connections</p>
            <button className="primary-btn" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', boxShadow: 'none' }}>
              Browse Files
            </button>
          </div>

          <div className="dropzone">
            <FileText size={32} color="var(--text-secondary)" style={{ marginBottom: 12 }} />
            <h4 style={{ fontWeight: 600, marginBottom: 4 }}>3. Context Logs (Optional)</h4>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)' }}>Active Directory, VPN auth, or host config logs</p>
            <button className="primary-btn" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)', boxShadow: 'none' }}>
              Browse Files
            </button>
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-4)', marginTop: 'var(--space-4)' }}>
            <button 
              onClick={() => setMode(null)}
              style={{ flex: 1, padding: 'var(--space-3)', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)', fontWeight: 600 }}
            >
              Back
            </button>
            <button 
              onClick={handleUploadComplete}
              className="primary-btn" style={{ flex: 2, margin: 0 }}
            >
              Process Logs & Launch
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
