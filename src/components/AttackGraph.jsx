import { useState, useCallback, useEffect, useContext } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  MarkerType,
  applyNodeChanges,
  applyEdgeChanges,
  Handle,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { AlertTriangle, Monitor, Globe, Users } from 'lucide-react';
import { Filter } from 'lucide-react';
import { ScenarioContext } from '../App';

// ── Node: Central attacker / external host ──
const AttackNode = ({ data }) => (
  <div className="attack-node" style={{
    borderColor: data.nodeType === 'attacker' ? 'rgba(239,68,68,0.35)' : 'var(--surface-border)',
    background: data.nodeType === 'attacker' ? 'rgba(239, 68, 68, 0.08)' : 'var(--bg-secondary)',
    minWidth: 120,
    padding: '7px 12px',
  }}>
    <Handle type="target" position={Position.Left} style={{ opacity: 0, width: 1, height: 1 }} />
    <Handle type="source" position={Position.Right} style={{ opacity: 0, width: 1, height: 1 }} />
    <Handle type="target" position={Position.Right} style={{ opacity: 0, width: 1, height: 1 }} id="target-right" />
    <Handle type="source" position={Position.Left} style={{ opacity: 0, width: 1, height: 1 }} id="source-left" />
    <div className={`attack-node-icon ${data.nodeType === 'attacker' ? 'attacker' : 'normal'}`}>
      {data.nodeType === 'attacker' ? <Monitor size={12} /> : <Globe size={12} />}
    </div>
    <div>
      <div style={{ fontWeight: 700, fontSize: 11 }}>{data.label}</div>
      {data.sublabel && (
        <div style={{ fontSize: 9, color: 'var(--text-tertiary)', marginTop: 1 }}>{data.sublabel}</div>
      )}
    </div>
  </div>
);

// ── Node: Attack type (red indicator pill) ──
const AttackTypeNode = ({ data }) => (
  <div className="attack-node" style={{
    borderColor: 'rgba(239,68,68,0.25)',
    background: 'rgba(239, 68, 68, 0.05)',
    padding: '5px 10px',
    minWidth: 110,
  }}>
    <Handle type="target" position={Position.Left} style={{ opacity: 0, width: 1, height: 1 }} />
    <Handle type="source" position={Position.Right} style={{ opacity: 0, width: 1, height: 1 }} />
    <Handle type="target" position={Position.Right} style={{ opacity: 0, width: 1, height: 1 }} id="target-right" />
    <Handle type="source" position={Position.Left} style={{ opacity: 0, width: 1, height: 1 }} id="source-left" />
    <div className="attack-node-icon attacker" style={{ width: 18, height: 18, borderRadius: 4 }}>
      <AlertTriangle size={9} />
    </div>
    <div style={{ fontWeight: 600, fontSize: 10.5, color: 'var(--text-primary)' }}>{data.label}</div>
  </div>
);

// ── Node: Target group count badge ──
const TargetGroupNode = ({ data }) => (
  <div className="attack-node" style={{
    borderColor: 'rgba(37,99,235,0.2)',
    background: 'rgba(37, 99, 235, 0.05)',
    padding: '5px 10px',
    minWidth: 100,
  }}>
    <Handle type="target" position={Position.Left} style={{ opacity: 0, width: 1, height: 1 }} />
    <Handle type="source" position={Position.Right} style={{ opacity: 0, width: 1, height: 1 }} />
    <Handle type="target" position={Position.Right} style={{ opacity: 0, width: 1, height: 1 }} id="target-right" />
    <Handle type="source" position={Position.Left} style={{ opacity: 0, width: 1, height: 1 }} id="source-left" />
    <div className="attack-node-icon target" style={{ width: 20, height: 20, fontSize: 10, fontWeight: 800, borderRadius: 4 }}>
      {data.count}
    </div>
    <div style={{ fontWeight: 600, fontSize: 10, color: 'var(--accent-primary)' }}>{data.label}</div>
    <Users size={10} style={{ color: '#93c5fd', marginLeft: 2 }} />
  </div>
);

const nodeTypes = {
  attackNode: AttackNode,
  attackTypeNode: AttackTypeNode,
  targetGroupNode: TargetGroupNode,
};

const defaultEdgeOptions = {
  type: 'smoothstep',
  style: { strokeWidth: 1.5 },
};

export default function AttackGraph({ data }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [perspective, setPerspective] = useState('logical');
  const { theme } = useContext(ScenarioContext);

  useEffect(() => {
    setNodes(data.graphNodes || []);
    setEdges(data.graphEdges || []);
  }, [data]);

  const onNodesChange = useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  );

  const onEdgesChange = useCallback(
    (changes) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    []
  );

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Toolbar */}
      <div className="focused-view-bar">
        <Filter size={15} color="var(--text-secondary)" />
        <span className="focused-label">Topology Controls</span>

        <span style={{ color: 'var(--surface-border)', margin: '0 6px' }}>|</span>

        <select
          value={perspective}
          onChange={e => setPerspective(e.target.value)}
          style={{ padding: '2px 8px', fontSize: '11px', borderRadius: '4px', border: '1px solid var(--surface-border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
        >
          <option value="logical">Logical View (Attack Path)</option>
          <option value="physical">Physical View (Subnets)</option>
        </select>

        <select
          style={{ padding: '2px 8px', fontSize: '11px', borderRadius: '4px', border: '1px solid var(--surface-border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
        >
          <option>Pivot: {data.hosts?.attacker?.ip || 'Attacker'}</option>
        </select>

        <button className="graph-legend-btn">Legend</button>
      </div>

      {/* Flow canvas */}
      <div style={{ flex: 1, position: 'relative', minHeight: 300 }} className="attack-graph-wrapper">
        <div style={{ position: 'absolute', inset: 0 }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            defaultEdgeOptions={defaultEdgeOptions}
            fitView
            fitViewOptions={{ padding: 0.18 }}
            attributionPosition="bottom-right"
            minZoom={0.3}
            maxZoom={2}
            proOptions={{ hideAttribution: true }}
          >
            <Background color={theme === 'dark' ? '#334155' : '#e2e8f0'} gap={20} size={1} variant="dots" />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      </div>
    </div>
  );
}
