import { Star, TrendingUp, Info, ExternalLink } from 'lucide-react';
import { hosts, attackProfile } from '../data/mockAttackScenario';

export default function HostDetailPanel({ compact = false }) {
  const host = hosts.attacker;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)', padding: compact ? 0 : 'var(--space-2)' }}>
      {/* Host Information */}
      {!compact && (
        <div className="info-section">
          <div className="info-row">
            <span className="info-row-label">Last Seen IP:</span>
            <span className="info-row-value"><a href="#">{host.ip}</a></span>
          </div>
          <div className="info-row">
            <span className="info-row-label">Sensor:</span>
            <span className="info-row-value">{host.sensor}</span>
          </div>
          <div className="info-row">
            <span className="info-row-label">Observed Privilege:</span>
            <span className="info-row-value">
              <span style={{ color: 'var(--severity-medium)' }}>★</span> {host.privilege} ⓘ
            </span>
          </div>
          <div className="info-row">
            <span className="info-row-label">Roles ⓘ:</span>
            <span className="info-row-value">{host.roles.join(', ')}</span>
          </div>
        </div>
      )}

      {/* Attack Profile */}
      <div style={{ 
        background: 'rgba(239, 68, 68, 0.05)', 
        border: '1px solid rgba(239, 68, 68, 0.2)', 
        borderRadius: 'var(--radius-md)', 
        padding: 'var(--space-3)' 
      }}>
        <div style={{ color: 'var(--severity-critical)', fontWeight: 700, fontSize: 'var(--text-sm)', marginBottom: 'var(--space-1)' }}>
          Attack Profile: {attackProfile.classification} ⓘ
        </div>
        {!compact && (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 'var(--space-2)' }}>
            {attackProfile.description}
          </div>
        )}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: 'var(--space-2)' }}>
          {attackProfile.positiveIndicators.slice(0, compact ? 2 : undefined).map((indicator) => (
            <span key={indicator} style={{ 
              fontSize: '10px', 
              background: 'white', 
              border: '1px solid var(--surface-border)', 
              padding: '2px 6px', 
              borderRadius: 'var(--radius-full)',
              color: 'var(--text-secondary)'
            }}>
              {indicator}
            </span>
          ))}
          {compact && attackProfile.positiveIndicators.length > 2 && (
            <span style={{ fontSize: '10px', color: 'var(--text-tertiary)', padding: '2px 6px' }}>+{attackProfile.positiveIndicators.length - 2} more</span>
          )}
        </div>
      </div>

      {/* Scoring Factors */}
      <div className="info-section">
        <div className="info-row">
          <span className="info-row-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>Entity Importance <Info size={12}/></span>
          <span className="info-row-value" style={{ color: 'var(--severity-medium)' }}>{host.entityImportance}</span>
        </div>
        <div className="info-row">
          <span className="info-row-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>Attack Rating <Info size={12}/></span>
          <span className="info-row-value" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ fontWeight: 800, color: 'var(--severity-critical)' }}>{host.attackRating}/10</span>
            <Star size={12} fill="var(--severity-critical)" color="var(--severity-critical)" />
          </span>
        </div>
        <div className="info-row">
          <span className="info-row-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>Velocity <Info size={12}/></span>
          <span className="info-row-value" style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--severity-high)' }}>
            <TrendingUp size={14} /> {host.velocity}
          </span>
        </div>
      </div>
    </div>
  );
}
