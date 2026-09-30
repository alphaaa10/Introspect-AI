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

  // Signed contribution: real SHAP (`shap`) when present, else fall back to the
  // mock shape ({value, direction}). Positive pushes toward the stage.
  const signedOf = (s) =>
    s.shap !== undefined ? s.shap : (s.direction === 'negative' ? -s.value : s.value);
  const labelOf = (s) => s.label || s.feature;

  const maxAbs = Math.max(...shapValues.map((s) => Math.abs(signedOf(s)))) || 1;
  const isReal = meta.method && meta.method.toLowerCase().includes('shap');

  return (
    <div style={{ padding: 'var(--space-2)', height: '100%', overflow: 'auto' }}>
      <div style={{ fontSize: 'var(--text-sm)', fontWeight: 700, marginBottom: 2 }}>
        {isReal ? 'SHAP attribution (LightGBM)' : 'Feature attribution'}
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: 'var(--space-3)', fontWeight: 500 }}>
        {meta.stage
          ? <>Explaining stage <b>{meta.stage}</b>{meta.confidence != null ? ` · confidence ${(meta.confidence * 100).toFixed(0)}%` : ''} · signed per-feature contribution</>
          : 'Signed per-feature contribution — bar length = magnitude'}
      </div>

      {shapValues.map((item) => {
        const signed = signedOf(item);
        const isPos = signed >= 0;
        return (
          <div key={item.feature} className="shap-bar-row">
            <span className="shap-feature">{labelOf(item)}</span>
            <div className="shap-bar-track">
              <div
                className={`shap-bar-fill ${isPos ? 'positive' : 'negative'}`}
                style={{ width: `${(Math.abs(signed) / maxAbs) * 100}%` }}
              />
            </div>
            <span className="shap-value" style={{ color: isPos ? 'var(--severity-critical)' : 'var(--accent-primary)' }}>
              {signed > 0 ? '+' : ''}{signed.toFixed(item.shap !== undefined ? 3 : 2)}
            </span>
          </div>
        );
      })}

      {/* Legend */}
      <div style={{ display: 'flex', gap: 'var(--space-4)', margin: 'var(--space-3) 0', fontSize: 10, color: 'var(--text-tertiary)' }}>
        <span>
          <span style={{ display: 'inline-block', width: 10, height: 8, background: 'var(--severity-critical)', borderRadius: 2, marginRight: 4 }} />
          Pushes toward this stage (+SHAP)
        </span>
        <span>
          <span style={{ display: 'inline-block', width: 10, height: 8, background: 'var(--accent-primary)', borderRadius: 2, marginRight: 4 }} />
          Pushes away (−SHAP)
        </span>
      </div>

      {isReal && meta.additivityResidual != null && (
        <div style={{ fontSize: 9, color: 'var(--text-tertiary)', marginBottom: 'var(--space-2)' }}>
          Exact TreeExplainer · additivity residual {Number(meta.additivityResidual).toExponential(1)}
        </div>
      )}

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
