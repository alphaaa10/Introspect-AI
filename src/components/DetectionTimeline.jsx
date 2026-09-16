import { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, Edit, Maximize2 } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';
import { formatDate } from '../data/mockAttackScenario';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: 'white',
        border: '1px solid var(--surface-border)',
        borderRadius: 'var(--radius-md)',
        padding: '8px 12px',
        fontSize: 'var(--text-xs)',
        boxShadow: 'var(--shadow-lg)',
      }}>
        <div style={{ color: 'var(--text-secondary)' }}>{label}</div>
        <div style={{ color: 'var(--severity-critical)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
          Risk Score: {payload[0].value}
        </div>
      </div>
    );
  }
  return null;
};

export default function DetectionTimeline({ data, onMaximize, isMaximized }) {
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [timeRange, setTimeRange] = useState('2W');

  const toggleRow = (id) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filteredTimeline = useMemo(() => {
    const fullData = data.urgencyTimeline || [];
    if (fullData.length === 0) return [];
    
    // Simulating data filtering based on range
    if (timeRange === '1D') return fullData.slice(-5);
    if (timeRange === '1W') return fullData.slice(-10);
    if (timeRange === '1M') {
      // expand the data to look like a month (just a mock replication)
      return [...fullData.map(d => ({...d, time: `Aug ${d.time}`})), ...fullData];
    }
    return fullData; // 2W default
  }, [timeRange, data.urgencyTimeline]);

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Timeline Chart */}
      <div style={{ padding: 'var(--space-4)', borderBottom: '1px solid var(--surface-border)', background: 'var(--bg-tertiary)', position: 'relative' }}>
        
        {onMaximize && (
          <button 
            onClick={onMaximize}
            style={{ position: 'absolute', top: 12, right: 12, color: 'var(--text-secondary)' }}
            title="Maximize View"
          >
            <Maximize2 size={16} />
          </button>
        )}

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 600 }}>Risk Timeline</span>
            <div style={{ display: 'flex', background: 'white', borderRadius: 'var(--radius-md)', padding: '2px', border: '1px solid var(--surface-border)' }}>
              {['1D', '1W', '2W', '1M'].map((range) => (
                <button
                  key={range}
                  style={{
                    padding: '2px 12px',
                    fontSize: '10px',
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    background: timeRange === range ? 'var(--accent-primary)' : 'transparent',
                    color: timeRange === range ? 'white' : 'var(--text-secondary)',
                  }}
                  onClick={() => setTimeRange(range)}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginRight: '24px' }}>
            <span style={{ color: 'var(--severity-critical)', fontWeight: 800 }}>—</span> Risk Score
          </div>
        </div>

        <div style={{ height: isMaximized ? 240 : 120, width: '100%', transition: 'height var(--transition-base)' }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={filteredTimeline} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
              <defs>
                <linearGradient id="urgencyGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="time"
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 10, fill: '#64748b' }}
                interval="preserveStartEnd"
              />
              <YAxis
                domain={[0, 100]}
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 10, fill: '#64748b' }}
                width={40}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="stepAfter"
                dataKey="value"
                stroke="#ef4444"
                strokeWidth={2}
                fill="url(#urgencyGradient)"
                dot={false}
                activeDot={{ r: 4, fill: '#ef4444', stroke: 'white', strokeWidth: 2 }}
                isAnimationActive={true}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Detection Table */}
      <div style={{ flex: 1, overflow: 'auto', background: 'white' }}>
        <div style={{ padding: 'var(--space-3) var(--space-4)', display: 'flex', gap: '12px', fontSize: 'var(--text-xs)' }}>
          <a href="#" style={{ fontWeight: 600 }}>Expand All</a>
          <span style={{ color: 'var(--surface-border)' }}>|</span>
          <a href="#" style={{ color: 'var(--text-secondary)' }}>Collapse All</a>
        </div>

        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 40 }}></th>
              <th>Category</th>
              <th>Type</th>
              <th>Status</th>
              <th>First Seen</th>
              <th>Last Seen ▾</th>
              <th style={{ width: 40 }}></th>
            </tr>
          </thead>
          <tbody>
            {(data.detections || []).map((det) => (
              <tr key={det.id}>
                <td style={{ textAlign: 'center' }}>
                  <button onClick={() => toggleRow(det.id)} style={{ color: 'var(--text-tertiary)' }}>
                    {expandedRows.has(det.id) ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                  </button>
                </td>
                <td>
                  <span className={`badge badge-${det.categoryClass}`}>
                    {det.category}
                  </span>
                </td>
                <td>
                  <a href="#" style={{ fontWeight: 600 }}>{det.type}</a>
                </td>
                <td>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontWeight: 600 }}>
                    <span style={{ 
                      width: 8, height: 8, borderRadius: '50%', 
                      background: det.statusClass === 'active' ? 'var(--severity-low)' : 'var(--text-tertiary)' 
                    }} />
                    {det.status}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{formatDate(det.firstSeen)}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{formatDate(det.lastSeen)}</td>
                <td>
                  <button style={{ color: 'var(--text-tertiary)' }} title="Edit">
                    <Edit size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
