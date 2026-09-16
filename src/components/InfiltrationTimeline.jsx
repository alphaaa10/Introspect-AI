import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  ReferenceLine, ReferenceArea
} from 'recharts';

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const d = payload[0].payload;
    return (
      <div style={{
        background: 'rgba(255,255,255,0.95)',
        backdropFilter: 'blur(12px)',
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
          color: d.probability > 0.7 ? 'var(--severity-critical)'
               : d.probability > 0.4 ? 'var(--severity-high)'
               : 'var(--severity-medium)',
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

export default function InfiltrationTimeline({ data }) {
  const timeline = data || [];
  const predStart = timeline.findIndex(d => d.type === 'predicted');
  const nowPoint = timeline.find(d => d.window === 'NOW');

  if (timeline.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-tertiary)', fontSize: 13 }}>
        No infiltration timeline data available
      </div>
    );
  }

  return (
    <div style={{ height: '100%', width: '100%', minHeight: 180 }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={timeline} margin={{ top: 12, right: 14, left: -12, bottom: 0 }}>
          <defs>
            <linearGradient id="probGradientA" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#2563eb" stopOpacity={0.18} />
              <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="predGradientA" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.12} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>

          {/* Predicted zone highlight */}
          {predStart > 0 && (
            <ReferenceArea
              x1={timeline[predStart].window}
              x2={timeline[timeline.length - 1].window}
              fill="rgba(239, 68, 68, 0.04)"
              stroke="none"
            />
          )}

          <XAxis
            dataKey="window"
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 9, fill: '#94a3b8' }}
            interval={1}
          />
          <YAxis
            domain={[0, 1]}
            axisLine={false}
            tickLine={false}
            tick={{ fontSize: 9, fill: '#94a3b8' }}
            tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
            width={38}
          />
          <Tooltip content={<CustomTooltip />} />

          {/* 50% threshold line */}
          <ReferenceLine
            y={0.5}
            stroke="var(--severity-high)"
            strokeDasharray="4 4"
            strokeWidth={1}
            label={{ value: '50%', fill: '#f97316', fontSize: 9, position: 'right' }}
          />

          {/* NOW marker */}
          {nowPoint && (
            <ReferenceLine
              x="NOW"
              stroke="var(--accent-primary)"
              strokeDasharray="3 3"
              strokeWidth={2}
              label={{ value: 'NOW', fill: '#2563eb', fontSize: 9, position: 'top' }}
            />
          )}

          <Area
            type="monotone"
            dataKey="probability"
            stroke="#2563eb"
            strokeWidth={2.5}
            fill="url(#probGradientA)"
            dot={(props) => {
              const { cx, cy, payload } = props;
              if (payload.type === 'predicted') {
                return (
                  <circle
                    key={payload.window}
                    cx={cx} cy={cy} r={3.5}
                    fill="var(--bg-secondary)"
                    stroke="#ef4444"
                    strokeWidth={2}
                    strokeDasharray="2 2"
                  />
                );
              }
              return (
                <circle
                  key={payload.window}
                  cx={cx} cy={cy} r={3.5}
                  fill="#2563eb"
                  stroke="var(--bg-secondary)"
                  strokeWidth={1.5}
                />
              );
            }}
            activeDot={{ r: 5, fill: '#1d4ed8', stroke: 'var(--bg-secondary)', strokeWidth: 2 }}
            isAnimationActive
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
