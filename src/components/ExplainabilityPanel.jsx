import { shapValues } from '../data/mockAttackScenario';

export default function ExplainabilityPanel() {
  const maxVal = Math.max(...shapValues.map(s => Math.abs(s.value)));

  return (
    <div style={{ padding: 'var(--space-2)' }}>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: 'var(--space-4)', fontWeight: 500 }}>
        Top features driving prediction (SHAP values)
      </div>
      {shapValues.map((item) => (
        <div key={item.feature} className="shap-bar-row">
          <span className="shap-feature">{item.feature}</span>
          <div className="shap-bar-track" style={{ background: 'var(--surface-divider)' }}>
            <div
              className={`shap-bar-fill ${item.direction}`}
              style={{ width: `${(Math.abs(item.value) / maxVal) * 100}%` }}
            />
          </div>
          <span className="shap-value">
            {item.value > 0 ? '+' : ''}{item.value.toFixed(2)}
          </span>
        </div>
      ))}
      <div style={{ marginTop: 'var(--space-6)', paddingTop: 'var(--space-4)', borderTop: '1px solid var(--surface-divider)' }}>
        <h4 style={{ fontSize: 'var(--text-sm)', fontWeight: 600, marginBottom: 'var(--space-2)' }}>Prediction Confidence</h4>
        <div className="info-row">
          <span className="info-row-label">Calibrated Probability:</span>
          <span className="info-row-value" style={{ color: 'var(--severity-critical)' }}>91%</span>
        </div>
        <div className="info-row">
          <span className="info-row-label">Confidence Level:</span>
          <span className="info-row-value" style={{ color: 'var(--severity-high)' }}>HIGH</span>
        </div>
        <div className="info-row">
          <span className="info-row-label">Evidence Match:</span>
          <span className="info-row-value" style={{ color: 'var(--severity-low)' }}>3/3 Correlation</span>
        </div>
      </div>
    </div>
  );
}
