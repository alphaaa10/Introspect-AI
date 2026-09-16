import { useState, createContext, useContext } from 'react';
import SetupScreen from './components/SetupScreen';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import HostDetailPanel from './components/HostDetailPanel';
import AttackGraph from './components/AttackGraph';
import DetectionTimeline from './components/DetectionTimeline';
import InfiltrationTimeline from './components/InfiltrationTimeline';
import MitreStageProgression from './components/MitreStageProgression';
import NarrativePanel from './components/NarrativePanel';
import ExplainabilityPanel from './components/ExplainabilityPanel';
import AnalystActions from './components/AnalystActions';
import AttackStoryReconstruction from './components/AttackStoryReconstruction';
import PipelineVisualization from './components/PipelineVisualization';
import OverviewDashboard from './components/OverviewDashboard';
import { scenarios } from './data/mockScenarios';

export const ScenarioContext = createContext();

export default function App() {
  const [appState, setAppState] = useState('setup');
  const [activeView, setActiveView] = useState('Overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [currentScenarioKey, setCurrentScenarioKey] = useState('A_BRUTE_FORCE');
  const [maximizedComponent, setMaximizedComponent] = useState(null);

  if (appState === 'setup') {
    return (
      <>
        <div className="mesh-bg" />
        <SetupScreen onComplete={(datasetKey) => {
          if (datasetKey !== 'upload') {
            setCurrentScenarioKey(datasetKey);
          }
          setAppState('dashboard');
        }} />
      </>
    );
  }

  const scenarioData = scenarios[currentScenarioKey];

  const handleMaximize = (componentId) => {
    setMaximizedComponent(maximizedComponent === componentId ? null : componentId);
  };

  const Wrapper = ({ id, children, className = '', style = {} }) => {
    const isMax = maximizedComponent === id;
    if (maximizedComponent && !isMax) return null;
    
    let finalClass = className;
    if (isMax) {
      finalClass = finalClass.replace('glass-panel', '').trim() + ' solid-panel maximized';
    }

    return (
      <>
        {isMax && <div className="maximized-backdrop" onClick={() => handleMaximize(id)} />}
        <div className={finalClass} style={isMax ? {} : style}>
          {children}
        </div>
      </>
    );
  };

  const renderNewOverview = () => (
    <OverviewDashboard data={scenarioData} />
  );

  const renderForecast = () => (
    <div style={{ display: 'flex', gap: 'var(--space-6)', height: '100%', width: '100%' }}>
      <Wrapper id="infiltration" className="glass-panel" style={{ flex: 2, display: 'flex', flexDirection: 'column' }}>
        <div className="panel-header">
          <span className="panel-title">Infiltration Forecast</span>
          <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={() => handleMaximize('infiltration')}>⛶</button>
        </div>
        <div className="panel-body">
          <InfiltrationTimeline data={scenarioData.infiltrationTimeline} />
        </div>
      </Wrapper>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        <Wrapper id="scoring" className="glass-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <div className="panel-header">
            <span className="panel-title">Scoring Factors</span>
            <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={() => handleMaximize('scoring')}>⛶</button>
          </div>
          <div className="panel-body">
            <HostDetailPanel compact data={scenarioData} />
          </div>
        </Wrapper>
      </div>
    </div>
  );

  const renderTopology = () => (
    <Wrapper id="topology" className="glass-panel" style={{ height: '100%', width: '100%' }}>
      <div className="panel-header">
        <span className="panel-title">Interactive Attack Graph</span>
        <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={() => handleMaximize('topology')}>⛶</button>
      </div>
      <div className="panel-body" style={{ padding: 0 }}>
        <AttackGraph data={scenarioData} />
      </div>
    </Wrapper>
  );

  const renderDetections = () => (
    <Wrapper id="detections" className="glass-panel" style={{ height: '100%', width: '100%' }}>
      <div className="panel-body" style={{ padding: 0, display: 'flex', flexDirection: 'column' }}>
        <DetectionTimeline data={scenarioData} onMaximize={() => handleMaximize('detections')} isMaximized={maximizedComponent === 'detections'} />
      </div>
    </Wrapper>
  );

  const renderProfiling = () => (
    <div style={{ display: 'flex', gap: 'var(--space-6)', height: '100%', width: '100%' }}>
      <Wrapper id="profiling_detail" className="glass-panel" style={{ flex: 1 }}>
        <div className="panel-header">
          <span className="panel-title">Entity Profiling</span>
          <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={() => handleMaximize('profiling_detail')}>⛶</button>
        </div>
        <div className="panel-body">
          <HostDetailPanel data={scenarioData} />
        </div>
      </Wrapper>
      <Wrapper id="profiling_shap" className="glass-panel" style={{ flex: 2 }}>
        <div className="panel-header">
          <span className="panel-title">Explainability (SHAP & Attention)</span>
          <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={() => handleMaximize('profiling_shap')}>⛶</button>
        </div>
        <div className="panel-body">
          <ExplainabilityPanel data={scenarioData.shapValues} />
        </div>
      </Wrapper>
    </div>
  );

  const renderReconstruction = () => (
    <Wrapper id="reconstruction" className="glass-panel" style={{ height: '100%', width: '100%' }}>
      <div className="panel-header">
        <span className="panel-title">Attack Story Reconstruction</span>
        <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={() => handleMaximize('reconstruction')}>⛶</button>
      </div>
      <div className="panel-body" style={{ padding: 0 }}>
        <AttackStoryReconstruction data={scenarioData} />
      </div>
    </Wrapper>
  );

  const renderPipeline = () => (
    <Wrapper id="pipeline" className="glass-panel" style={{ height: '100%', width: '100%' }}>
      <div className="panel-header">
        <span className="panel-title">AI Processing Pipeline (Live)</span>
        <button className="icon-btn" style={{ width: 24, height: 24 }} onClick={() => handleMaximize('pipeline')}>⛶</button>
      </div>
      <div className="panel-body" style={{ padding: 0 }}>
        <PipelineVisualization />
      </div>
    </Wrapper>
  );

  return (
    <ScenarioContext.Provider value={{ currentScenarioKey, setCurrentScenarioKey, scenarios }}>
      <div className="mesh-bg" />
      <div className="app-layout">
        <Sidebar 
          collapsed={sidebarCollapsed} 
          onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
          activeView={activeView}
          onViewChange={setActiveView}
        />

        <div className="main-area">
          <div className="topbar-wrapper">
            <TopBar data={scenarioData} />
          </div>

          <div className="content-wrapper">
            {activeView === 'Overview' && renderNewOverview()}
            {activeView === 'Forecast' && renderForecast()}
            {activeView === 'Topology' && renderTopology()}
            {activeView === 'Detections' && renderDetections()}
            {activeView === 'Profiling' && renderProfiling()}
            {activeView === 'Reconstruction' && renderReconstruction()}
            {activeView === 'Pipeline' && renderPipeline()}
          </div>
        </div>
      </div>
    </ScenarioContext.Provider>
  );
}
