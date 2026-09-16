import { useState, useCallback, useEffect, useContext } from 'react';
import ReactFlow, { 
  Background, 
  MarkerType, 
  Position,
  Handle
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Database, Network, Cpu, BrainCircuit, Search, Split, FileText } from 'lucide-react';
import { ScenarioContext } from '../App';

const PipelineNode = ({ data }) => {
  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: `2px solid ${data.color || 'var(--surface-border)'}`,
      borderRadius: 'var(--radius-lg)',
      padding: 'var(--space-3) var(--space-4)',
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      boxShadow: 'var(--shadow-md)',
      minWidth: '220px'
    }}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div style={{ 
        width: 32, height: 32, borderRadius: 'var(--radius-sm)', 
        background: `${data.color}20`, color: data.color,
        display: 'flex', alignItems: 'center', justifyContent: 'center'
      }}>
        {data.icon}
      </div>
      <div>
        <div style={{ fontSize: '11px', fontWeight: 800, color: 'var(--text-primary)', textTransform: 'uppercase' }}>{data.label}</div>
        <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>{data.subtext}</div>
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
      
      {/* Additional handles for complex routing */}
      <Handle type="source" position={Position.Bottom} id="bottom" style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Top} id="top" style={{ opacity: 0 }} />
    </div>
  );
};

const nodeTypes = { pipelineNode: PipelineNode };

const initialNodes = [
  { id: '1', type: 'pipelineNode', position: { x: 50, y: 150 }, data: { label: 'Raw Logs / PCAP', subtext: 'Ingestion Layer', icon: <Database size={16}/>, color: '#64748b' } },
  { id: '2', type: 'pipelineNode', position: { x: 350, y: 50 }, data: { label: 'Graph Construction', subtext: '60s Time Windows', icon: <Network size={16}/>, color: '#3b82f6' } },
  { id: '3', type: 'pipelineNode', position: { x: 650, y: 50 }, data: { label: 'GNN + LSTM', subtext: 'World Model', icon: <BrainCircuit size={16}/>, color: '#8b5cf6' } },
  { id: '4', type: 'pipelineNode', position: { x: 950, y: 50 }, data: { label: 'Prediction Engine', subtext: 'K-Step Rollout', icon: <Cpu size={16}/>, color: '#ef4444' } },
  
  { id: '5', type: 'pipelineNode', position: { x: 650, y: 250 }, data: { label: 'Correlation Engine', subtext: 'Entity Graphing', icon: <Search size={16}/>, color: '#eab308' } },
  { id: '6', type: 'pipelineNode', position: { x: 950, y: 250 }, data: { label: 'Fusion Layer', subtext: 'Bayesian Calib.', icon: <Split size={16}/>, color: '#10b981' } },
  { id: '7', type: 'pipelineNode', position: { x: 1250, y: 150 }, data: { label: 'Narrative Gen', subtext: 'Grounded LLM', icon: <FileText size={16}/>, color: '#0ea5e9' } },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2', animated: true, style: { stroke: '#3b82f6', strokeWidth: 2 } },
  { id: 'e2-3', source: '2', target: '3', animated: true, style: { stroke: '#8b5cf6', strokeWidth: 2 } },
  { id: 'e3-4', source: '3', target: '4', animated: true, style: { stroke: '#ef4444', strokeWidth: 2 } },
  
  { id: 'e1-5', source: '1', target: '5', sourceHandle: 'bottom', animated: true, style: { stroke: '#eab308', strokeWidth: 2 } },
  
  { id: 'e4-5', source: '4', target: '5', sourceHandle: 'bottom', targetHandle: 'top', animated: true, label: 'Focus Signal', style: { stroke: '#ef4444', strokeWidth: 2, strokeDasharray: '5 5' } },
  
  { id: 'e4-6', source: '4', target: '6', animated: true, style: { stroke: '#ef4444', strokeWidth: 2 } },
  { id: 'e5-6', source: '5', target: '6', animated: true, label: 'Evidence', style: { stroke: '#eab308', strokeWidth: 2 } },
  
  { id: 'e6-7', source: '6', target: '7', animated: true, style: { stroke: '#10b981', strokeWidth: 2 } },
];

export default function PipelineVisualization() {
  const { theme } = useContext(ScenarioContext);

  return (
    <div style={{ width: '100%', flex: 1, minHeight: 400, background: 'var(--bg-primary)', position: 'relative' }}>
      <div style={{ position: 'absolute', inset: 0 }}>
        <ReactFlow
          nodes={initialNodes}
          edges={initialEdges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          attributionPosition="bottom-right"
          edgesUpdatable={false}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color={theme === 'dark' ? '#334155' : '#cbd5e1'} gap={20} size={1} />
        </ReactFlow>
      </div>
      
      <div style={{ position: 'absolute', bottom: 24, left: 24, background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px', boxShadow: 'var(--shadow-lg)', maxWidth: 350, border: '1px solid var(--surface-border)' }}>
        <h4 style={{ fontSize: '12px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-primary)' }}>How It Works</h4>
        <p style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          The <strong>World Model</strong> (Top Path) predicts network state evolution. If danger is predicted, it sends a Focus Signal to the <strong>Correlation Engine</strong> (Bottom Path) to instantly hunt for hard evidence. The <strong>Fusion Layer</strong> calibrates the prediction based on evidence before the LLM generates a grounded narrative.
        </p>
      </div>
    </div>
  );
}
