import { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, Edit, Maximize2 } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts';
import { formatDate } from '../data/mockScenarios';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: 'var(--bg-secondary)',
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
    if (timeRange === '1D') return fullData.slice(-4);
    if (timeRange === '1W') return fullData.slice(-8);
    if (timeRange === '1M') return [...fullData.map(d => ({ ...d, time: `Ext ${d.time}` })), ...fullData];
    return fullData;
  }, [timeRange, data.urgencyTimeline]);

  const detections = data.detections || [];

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Risk Timeline Chart ── */}
      <div style={{
        padding: 'var(--space-4)',
        borderBottom: '1px solid var(--surface-border)',
        background: 'var(--bg-secondary)',
        position: 'relative',
        flexShrink: 0,
      }}>
        {onMaximize && (
          <button
            onClick={onMaximize}
            style={{ position: 'absolute', top: 12, right: 12, color: 'var(--text-secondary)' }}
            title="Maximize View"
          >
            <Maximize2 size={15} />
          </button>
        )}

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontWeight: 600 }}>
              Risk Timeline
            </span>
            <div style={{ display: 'flex', background: 'var(--bg-tertiary)', borderRadius: 'var(--radius-md)', padding: '2px', border: '1px solid var(--surface-border)' }}>
              {['1D', '1W', '2W', '1M'].map((range) => (
                <button
                  key={range}
                  style={{
                    padding: '2px 10px',
                    fontSize: 10,
                    fontWeight: 600,
                    borderRadius: 'var(--radius-sm)',
                    background: timeRange === range ? 'var(--accent-primary)' : 'transparent',
                    color: timeRange === range ? 'var(--bg-primary)' : 'var(--text-secondary)',
                    transition: 'all 0.15s',
                  }}
                  onClick={() => setTimeRange(range)}
                >
                  {range}
                </button>
              ))}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginRight: 28 }}>
            <span style={{ color: 'var(--severity-critical)', fontWeight: 800 }}>—</span>
            Risk Score (0–100)
          </div>
        </div>

        <div style={{ height: isMaximized ? 220 : 110, width: '100%', transition: 'height var(--transition-base)' }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={filteredTimeline} margin={{ top: 5, right: 10, left: -22, bottom: 0 }}>
              <defs>
                <linearGradient id="urgencyGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.18} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="time"
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 9, fill: '#94a3b8' }}
                interval="preserveStartEnd"
              />
              <YAxis
                domain={[0, 100]}
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 9, fill: '#94a3b8' }}
                width={36}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="stepAfter"
                dataKey="value"
                stroke="#ef4444"
                strokeWidth={2}
                fill="url(#urgencyGrad)"
                dot={false}
                activeDot={{ r: 4, fill: '#ef4444', stroke: 'var(--bg-secondary)', strokeWidth: 2 }}
                isAnimationActive
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Detection Table ── */}
      <div style={{ flex: 1, overflow: 'auto', background: 'var(--bg-secondary)' }}>
        <div style={{ padding: 'var(--space-2) var(--space-4)', display: 'flex', gap: 12, fontSize: 'var(--text-xs)', borderBottom: '1px solid var(--surface-divider)' }}>
          <a href="#" style={{ fontWeight: 600 }} onClick={e => { e.preventDefault(); setExpandedRows(new Set(detections.map(d => d.id))); }}>
            Expand All
          </a>
          <span style={{ color: 'var(--surface-border)' }}>|</span>
          <a href="#" style={{ color: 'var(--text-secondary)' }} onClick={e => { e.preventDefault(); setExpandedRows(new Set()); }}>
            Collapse All
          </a>
          <span style={{ marginLeft: 'auto', color: 'var(--text-tertiary)' }}>
            {detections.length} detection{detections.length !== 1 ? 's' : ''}
          </span>
        </div>

        <div className="table-scroll-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 36 }} />
                <th>Category</th>
                <th>Type</th>
                <th>Status</th>
                <th>First Seen</th>
                <th>Last Seen ▾</th>
                <th style={{ width: 36 }} />
              </tr>
            </thead>
            <tbody>
              {detections.map((det) => (
                <tr key={det.id}>
                  <td style={{ textAlign: 'center' }}>
                    <button onClick={() => toggleRow(det.id)} style={{ color: 'var(--text-tertiary)' }}>
                      {expandedRows.has(det.id) ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    </button>
                  </td>
                  <td>
                    <span className={`badge badge-${det.categoryClass}`}>
                      {det.category}
                    </span>
                  </td>
                  <td>
                    <a href="#" style={{ fontWeight: 600, fontSize: 'var(--text-xs)' }}>{det.type}</a>
                  </td>
                  <td>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 600 }}>
                      <span style={{
                        width: 7, height: 7, borderRadius: '50%',
                        background: det.statusClass === 'active' ? 'var(--severity-low)'
                          : det.statusClass === 'fixed' ? 'var(--accent-primary)'
                          : 'var(--text-tertiary)',
                      }} />
                      {det.status}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{formatDate(det.firstSeen)}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>{formatDate(det.lastSeen)}</td>
                  <td>
                    <button style={{ color: 'var(--text-tertiary)' }} title="Edit">
                      <Edit size={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
