import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  ReferenceLine, ReferenceArea
} from 'recharts';
import { infiltrationTimeline } from '../data/mockAttackScenario';

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const d = payload[0].payload;
    return (
      <div style={{
        background: 'rgba(255, 255, 255, 0.9)',
        backdropFilter: 'blur(8px)',
        border: '1px solid var(--surface-border)',
        borderRadius: 'var(--radius-md)',
        padding: '8px 12px',
        fontSize: 'var(--text-xs)',
        boxShadow: 'var(--shadow-lg)',
      }}>
        <div style={{ color: 'var(--text-secondary)', marginBottom: 2 }}>
          {d.window} ({d.time})
        </div>
        <div style={{
          color: d.probability > 0.7 ? 'var(--severity-critical)' :
                 d.probability > 0.4 ? 'var(--severity-high)' :
                 'var(--severity-medium)',
          fontWeight: 700,
          fontFamily: 'var(--font-mono)',
        }}>
          {(d.probability * 100).toFixed(0)}% — {d.tactic}
        </div>
        {d.type === 'predicted' && (
          <div style={{ color: 'var(--text-tertiary)', fontSize: '10px', marginTop: 2 }}>
            ⚠ Predicted (K-step rollout)
          </div>
        )}
      </div>
    );
  }
  return null;
};

export default function InfiltrationTimeline() {
  const predStart = infiltrationTimeline.findIndex(d => d.type === 'predicted');

  return (
    <div style={{ height: '100%', width: '100%', minHeight: 150 }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={infiltrationTimeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="probGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#2563eb" stopOpacity={0.2} />
              <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="predGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.15} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>

          {predStart > 0 && (
            <ReferenceArea
              x1={infiltrationTimeline[predStart].window}
              x2={infiltrationTimeline[infiltrationTimeline.length - 1].window}
              fill="rgba(239, 68, 68, 0.05)"
              stroke="none"
            />
          )}

          <XAxis
            dataKey="window"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 9, fill: '#94a3b8' }}
          />
          <YAxis
            domain={[0, 1]}
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 9, fill: '#94a3b8' }}
            tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
            width={35}
          />
          <Tooltip content={<CustomTooltip />} />

          <ReferenceLine
            y={0.5}
            stroke="var(--severity-high)"
            strokeDasharray="4 4"
            strokeWidth={1}
          />

          <ReferenceLine
            x="NOW"
            stroke="var(--accent-primary)"
            strokeDasharray="3 3"
            strokeWidth={2}
          />

          <Area
            type="monotone"
            dataKey="probability"
            stroke="#2563eb"
            strokeWidth={3}
            fill="url(#probGradient)"
            dot={(props) => {
              const { cx, cy, payload } = props;
              if (payload.type === 'predicted') {
                return (
                  <circle
                    key={payload.window}
                    cx={cx}
                    cy={cy}
                    r={3}
                    fill="white"
                    stroke="#ef4444"
                    strokeWidth={2}
                    strokeDasharray="2 2"
                  />
                );
              }
              return (
                <circle
                  key={payload.window}
                  cx={cx}
                  cy={cy}
                  r={3}
                  fill="#2563eb"
                  stroke="white"
                  strokeWidth={2}
                />
              );
            }}
            activeDot={{ r: 5, fill: '#1d4ed8', stroke: 'white', strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
