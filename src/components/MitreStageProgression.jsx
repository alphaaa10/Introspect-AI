import { mitreStages } from '../data/mockAttackScenario';

export default function MitreStageProgression() {
  return (
    <div className="mitre-progression">
      {mitreStages.map((stage, i) => (
        <div key={stage.id} style={{ display: 'flex', alignItems: 'center' }}>
          <div className="mitre-stage">
            <div className={`mitre-stage-box ${stage.status}`}>
              <div className="mitre-stage-icon">
                {stage.status === 'confirmed' ? '✓' : stage.status === 'current' ? '⚡' : stage.icon}
              </div>
              <div className="mitre-stage-name">{stage.shortName}</div>
              {stage.probability && (
                <div className="mitre-stage-prob">{(stage.probability * 100).toFixed(0)}%</div>
              )}
            </div>
          </div>
          {i < mitreStages.length - 1 && (
            <div className={`mitre-connector ${stage.status === 'confirmed' || stage.status === 'current' ? 'active' : ''}`} />
          )}
        </div>
      ))}
    </div>
  );
}
