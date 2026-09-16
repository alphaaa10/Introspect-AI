export default function ExplainabilityPanel({ data, explainabilityMeta }) {
  const shapValues = data || [];
  const meta = explainabilityMeta || { calibratedProbability: 'N/A', confidenceLevel: 'N/A', evidenceMatch: 'N/A' };

  if (shapValues.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-tertiary)', fontSize: 13 }}>
        No SHAP data available for this scenario
      </div>
    );
  }

  const maxVal = Math.max(...shapValues.map(s => Math.abs(s.value)));

  return (
    <div style={{ padding: 'var(--space-2)', height: '100%', overflow: 'auto' }}>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: 'var(--space-4)', fontWeight: 500 }}>
        Top features driving prediction (SHAP values) — higher bar = stronger influence
      </div>

      {shapValues.map((item) => (
        <div key={item.feature} className="shap-bar-row">
          <span className="shap-feature">{item.feature}</span>
          <div className="shap-bar-track">
            <div
              className={`shap-bar-fill ${item.direction}`}
              style={{ width: `${(Math.abs(item.value) / maxVal) * 100}%` }}
            />
          </div>
          <span className="shap-value" style={{ color: item.direction === 'positive' ? 'var(--severity-critical)' : 'var(--accent-primary)' }}>
            {item.value > 0 ? '+' : ''}{item.value.toFixed(2)}
          </span>
        </div>
      ))}

      {/* Legend */}
      <div style={{ display: 'flex', gap: 'var(--space-4)', margin: 'var(--space-3) 0', fontSize: 10, color: 'var(--text-tertiary)' }}>
        <span>
          <span style={{ display: 'inline-block', width: 10, height: 8, background: 'var(--severity-critical)', borderRadius: 2, marginRight: 4 }} />
          Risk-increasing feature
        </span>
        <span>
          <span style={{ display: 'inline-block', width: 10, height: 8, background: 'var(--accent-primary)', borderRadius: 2, marginRight: 4 }} />
          Risk-decreasing feature
        </span>
      </div>

      <div style={{ marginTop: 'var(--space-4)', paddingTop: 'var(--space-4)', borderTop: '1px solid var(--surface-divider)' }}>
        <h4 style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 'var(--space-3)' }}>
          Prediction Confidence
        </h4>
        <div className="info-row">
          <span className="info-row-label">Calibrated Probability:</span>
          <span className="info-row-value" style={{ color: 'var(--severity-critical)' }}>
            {meta.calibratedProbability}
          </span>
        </div>
        <div className="info-row">
          <span className="info-row-label">Confidence Level:</span>
          <span className="info-row-value" style={{ color: meta.confidenceLevel === 'HIGH' ? 'var(--severity-low)' : 'var(--severity-medium)' }}>
            {meta.confidenceLevel}
          </span>
        </div>
        <div className="info-row">
          <span className="info-row-label">Evidence Match:</span>
          <span className="info-row-value" style={{ color: 'var(--severity-low)' }}>
            {meta.evidenceMatch}
          </span>
        </div>
      </div>
    </div>
  );
}
