import { useState, useCallback, useEffect } from 'react';
import ReactFlow, { 
  Controls, 
  Background, 
  MarkerType, 
  applyNodeChanges, 
  applyEdgeChanges 
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Target, AlertTriangle, Monitor, Server, Filter, Globe, Users } from 'lucide-react';

// Node: Attacker or normal host
const AttackNode = ({ data }) => (
  <div className="attack-node">
    <div className={`attack-node-icon ${data.nodeType === 'attacker' ? 'attacker' : 'normal'}`}>
      {data.nodeType === 'attacker' ? <Monitor size={14} /> : <Globe size={14} />}
    </div>
    <div>
      <div style={{ fontWeight: 700 }}>{data.label}</div>
      {data.sublabel && <div style={{ fontSize: '9px', color: 'var(--text-tertiary)', marginTop: '-2px' }}>{data.sublabel}</div>}
    </div>
  </div>
);

// Node: Attack type (red-tinted indicator)
const AttackTypeNode = ({ data }) => (
  <div className="attack-node" style={{ borderColor: 'rgba(239, 68, 68, 0.3)', background: 'rgba(239, 68, 68, 0.05)' }}>
    <div className="attack-node-icon attacker" style={{ width: 20, height: 20 }}>
      <AlertTriangle size={10} />
    </div>
    <div style={{ fontWeight: 700 }}>{data.label}</div>
  </div>
);

// Node: Target group (blue count badge)
const TargetGroupNode = ({ data }) => (
  <div className="attack-node" style={{ borderColor: 'rgba(37, 99, 235, 0.3)', background: 'rgba(37, 99, 235, 0.05)' }}>
    <div className="attack-node-icon target" style={{ width: 20, height: 20, fontSize: '9px', fontWeight: 800 }}>
      {data.count}
    </div>
    <div style={{ fontWeight: 700, fontSize: '10px' }}>{data.label}</div>
  </div>
);

const nodeTypes = {
  attackNode: AttackNode,
  attackTypeNode: AttackTypeNode,
  targetGroupNode: TargetGroupNode,
};

const defaultEdgeOptions = {
  type: 'default',
  style: { stroke: '#94a3b8', strokeWidth: 1.5 },
  markerEnd: { type: MarkerType.ArrowClosed, color: '#94a3b8', width: 12, height: 12 },
};

export default function AttackGraph({ data }) {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [perspective, setPerspective] = useState('logical');

  useEffect(() => {
    setNodes(data.initialNodes || []);
    setEdges(data.initialEdges || []);
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
      <div className="focused-view-bar">
        <Filter size={16} color="var(--text-secondary)" />
        <span className="focused-label">Topology Controls</span>
        
        <span style={{ color: 'var(--surface-border)', margin: '0 8px' }}>|</span>
        
        <select value={perspective} onChange={e => setPerspective(e.target.value)} style={{ padding: '2px 8px', fontSize: '11px', borderRadius: '4px', border: '1px solid var(--surface-border)' }}>
          <option value="logical">Logical View (Attack Path)</option>
          <option value="physical">Physical View (Subnets)</option>
        </select>
        
        <select style={{ padding: '2px 8px', fontSize: '11px', borderRadius: '4px', border: '1px solid var(--surface-border)' }}>
          <option>Pivot: {data.hosts?.attacker?.ip || 'Attacker'}</option>
          <option>Pivot: Web Server</option>
          <option>Pivot: DB Cluster</option>
        </select>

        <button className="graph-legend-btn" style={{ marginLeft: 'auto' }}>
          Legend
        </button>
      </div>

      <div style={{ flex: 1, position: 'relative', minHeight: 0 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          defaultEdgeOptions={defaultEdgeOptions}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          attributionPosition="bottom-right"
        >
          <Background color="var(--surface-border)" gap={16} size={1} />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  );
}

