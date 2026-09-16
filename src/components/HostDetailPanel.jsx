import { Star, TrendingUp, Info } from 'lucide-react';

export default function HostDetailPanel({ data, compact = false }) {
  const host = data?.hosts?.attacker;
  const attackProfile = data?.attackProfile;

  if (!host || !attackProfile) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-tertiary)', fontSize: 13 }}>
        No host data available
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)', padding: compact ? 0 : 'var(--space-2)' }}>

      {/* Host Information */}
      {!compact && (
        <div className="info-section">
          <div className="info-row">
            <span className="info-row-label">Host / IP:</span>
            <span className="info-row-value" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
              {host.ip}
            </span>
          </div>
          <div className="info-row">
            <span className="info-row-label">Hostname:</span>
            <span className="info-row-value">{host.hostname}</span>
          </div>
          <div className="info-row">
            <span className="info-row-label">OS:</span>
            <span className="info-row-value">{host.os}</span>
          </div>
          <div className="info-row">
            <span className="info-row-label">Sensor:</span>
            <span className="info-row-value">{host.sensor}</span>
          </div>
          <div className="info-row">
            <span className="info-row-label">Observed Privilege:</span>
            <span className="info-row-value">
              <span style={{ color: 'var(--severity-medium)' }}>★</span> {host.privilege}
            </span>
          </div>
          <div className="info-row">
            <span className="info-row-label">Roles:</span>
            <span className="info-row-value" style={{ fontSize: 12, textAlign: 'right' }}>
              {host.roles?.join(', ')}
            </span>
          </div>
        </div>
      )}

      {/* Attack Profile */}
      <div style={{
        background: 'rgba(239,68,68,0.04)',
        border: '1px solid rgba(239,68,68,0.15)',
        borderRadius: 'var(--radius-md)',
        padding: 'var(--space-3)',
      }}>
        <div style={{ color: 'var(--severity-critical)', fontWeight: 700, fontSize: 'var(--text-sm)', marginBottom: 'var(--space-1)' }}>
          {attackProfile.classification}
        </div>
        {!compact && (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 'var(--space-2)', lineHeight: 1.5 }}>
            {attackProfile.description}
          </div>
        )}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: 'var(--space-1)' }}>
          {(compact ? attackProfile.positiveIndicators.slice(0, 3) : attackProfile.positiveIndicators).map((indicator) => (
            <span key={indicator} style={{
              fontSize: '10px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--surface-border)',
              padding: '2px 7px',
              borderRadius: 'var(--radius-full)',
              color: 'var(--text-secondary)',
              fontWeight: 500,
            }}>
              {indicator}
            </span>
          ))}
          {compact && attackProfile.positiveIndicators.length > 3 && (
            <span style={{ fontSize: '10px', color: 'var(--text-tertiary)', padding: '2px 4px' }}>
              +{attackProfile.positiveIndicators.length - 3} more
            </span>
          )}
        </div>
      </div>

      {/* Scoring Factors */}
      <div className="info-section">
        <div className="info-row">
          <span className="info-row-label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            Entity Importance <Info size={11} />
          </span>
          <span className="info-row-value" style={{ color: 'var(--severity-medium)' }}>
            {host.entityImportance}
          </span>
        </div>
        <div className="info-row">
          <span className="info-row-label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            Attack Rating <Info size={11} />
          </span>
          <span className="info-row-value" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ fontWeight: 800, color: 'var(--severity-critical)', fontSize: 15 }}>
              {host.attackRating}
            </span>
            <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>/10</span>
            <Star size={11} fill="var(--severity-critical)" color="var(--severity-critical)" />
          </span>
        </div>
        <div className="info-row">
          <span className="info-row-label" style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            Velocity <Info size={11} />
          </span>
          <span className="info-row-value" style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--severity-high)' }}>
            <TrendingUp size={13} /> {host.velocity}
          </span>
        </div>
        {!compact && (
          <div className="info-row">
            <span className="info-row-label">Risk Score</span>
            <span className="info-row-value" style={{ fontWeight: 800, color: 'var(--severity-critical)', fontSize: 15 }}>
              {host.urgencyScore}
              <span style={{ fontSize: 10, fontWeight: 400, color: 'var(--text-tertiary)', marginLeft: 2 }}>/100</span>
            </span>
          </div>
        )}
        {!compact && (
          <div className="info-row">
            <span className="info-row-label">Status</span>
            <span className="info-row-value" style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>
              {host.priorityStatus}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
