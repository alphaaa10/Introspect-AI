import { useState, createContext, useContext, useEffect } from 'react';
import SetupScreen from './components/SetupScreen';
import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';
import HostDetailPanel from './components/HostDetailPanel';
import AttackGraph from './components/AttackGraph';
import DetectionTimeline from './components/DetectionTimeline';
import InfiltrationTimeline from './components/InfiltrationTimeline';
import NarrativePanel from './components/NarrativePanel';
import ExplainabilityPanel from './components/ExplainabilityPanel';
import AnalystActions from './components/AnalystActions';
import AttackStoryReconstruction from './components/AttackStoryReconstruction';
import PipelineVisualization from './components/PipelineVisualization';
import OverviewDashboard from './components/OverviewDashboard';
import { scenarios } from './data/mockScenarios';
import { Menu, X } from 'lucide-react';

export const ScenarioContext = createContext();

export default function App() {
  const [appState, setAppState] = useState('setup');
  const [activeView, setActiveView] = useState('Overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [currentScenarioKey, setCurrentScenarioKey] = useState('A_BRUTE_FORCE');
  const [maximizedComponent, setMaximizedComponent] = useState(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('app-theme') || 'light';
  });

  useEffect(() => {
    if (theme === 'dark') {
      document.body.classList.add('dark');
    } else {
      document.body.classList.remove('dark');
    }
    localStorage.setItem('app-theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  if (appState === 'setup' || appState === 'select-dataset') {
    return (
      <>
        <div className="mesh-bg" />
        <SetupScreen 
          initialMode={appState === 'select-dataset' ? 'select-dataset' : null}
          onComplete={(datasetKey) => {
            if (datasetKey !== 'upload') setCurrentScenarioKey(datasetKey);
            setAppState('dashboard');
          }} 
        />
      </>
    );
  }

  const scenarioData = scenarios[currentScenarioKey] || scenarios['A_BRUTE_FORCE'];

  const handleMaximize = (componentId) => {
    setMaximizedComponent(maximizedComponent === componentId ? null : componentId);
  };

  const Wrapper = ({ id, children, className = '', style = {} }) => {
    const isMax = maximizedComponent === id;
    if (maximizedComponent && !isMax) return null;

    let finalClass = className;
    if (isMax) {
      finalClass = finalClass.replace('glass-panel', '').replace('solid-panel', '').trim() + ' solid-panel maximized';
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

  // ── Panel header helper ──
  const PanelHeader = ({ title, panelId }) => (
    <div className="panel-header">
      <span className="panel-title">{title}</span>
      <button
        className="icon-btn"
        style={{ width: 28, height: 28, fontSize: 14 }}
        onClick={() => handleMaximize(panelId)}
        title={maximizedComponent === panelId ? 'Restore' : 'Maximize'}
      >
        ⛶
      </button>
    </div>
  );

  // ── VIEW RENDERERS ──

  const renderOverview = () => (
    <div style={{ width: '100%', overflow: 'auto' }}>
      <OverviewDashboard data={scenarioData} />
    </div>
  );

  const renderForecast = () => (
    <div
      className="forecast-layout"
      style={{ display: 'flex', gap: 'var(--space-4)', width: '100%', minHeight: 0 }}
    >
      {/* Infiltration Timeline — main chart */}
      <Wrapper
        id="infiltration"
        className="solid-panel"
        style={{ flex: 2, display: 'flex', flexDirection: 'column', minHeight: 300 }}
      >
        <PanelHeader title="Infiltration Forecast" panelId="infiltration" />
        <div className="panel-body" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 250 }}>
          {/* Legend row */}
          <div style={{ display: 'flex', gap: 'var(--space-4)', marginBottom: 'var(--space-3)', fontSize: 11, flexWrap: 'wrap' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ display: 'inline-block', width: 20, height: 3, background: '#2563eb', borderRadius: 2 }} />
              Observed
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ display: 'inline-block', width: 20, height: 3, background: '#ef4444', borderRadius: 2, borderStyle: 'dashed' }} />
              Predicted (K-step)
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ display: 'inline-block', width: 2, height: 16, background: '#2563eb', borderRadius: 1 }} />
              Current (NOW)
            </span>
          </div>
          {/* Chart fills the rest */}
          <div style={{ flex: 1, minHeight: 200, position: 'relative' }}>
            <div style={{ position: 'absolute', inset: 0 }}>
              <InfiltrationTimeline data={scenarioData.infiltrationTimeline} />
            </div>
          </div>
        </div>
      </Wrapper>

      {/* Scoring / Host detail */}
      <Wrapper
        id="scoring"
        className="solid-panel"
        style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 300 }}
      >
        <PanelHeader title="Scoring Factors" panelId="scoring" />
        <div className="panel-body" style={{ overflow: 'auto' }}>
          <HostDetailPanel compact data={scenarioData} />
        </div>
      </Wrapper>
    </div>
  );

  const renderTopology = () => (
    <Wrapper id="topology" className="solid-panel" style={{ minHeight: 400, width: '100%' }}>
      <PanelHeader title="Interactive Attack Graph" panelId="topology" />
      <div className="panel-body attack-graph-wrapper" style={{ padding: 0, flex: 1, minHeight: 360, display: 'flex', flexDirection: 'column' }}>
        <AttackGraph data={scenarioData} />
      </div>
    </Wrapper>
  );

  const renderDetections = () => (
    <Wrapper id="detections" className="solid-panel" style={{ minHeight: 500, width: '100%' }}>
      <div className="panel-body" style={{ padding: 0, flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <DetectionTimeline
          data={scenarioData}
          onMaximize={() => handleMaximize('detections')}
          isMaximized={maximizedComponent === 'detections'}
        />
      </div>
    </Wrapper>
  );

  const renderProfiling = () => (
    <div
      className="profiling-layout"
      style={{ display: 'flex', gap: 'var(--space-4)', width: '100%' }}
    >
      <Wrapper id="profiling_detail" className="solid-panel" style={{ flex: 1, minHeight: 300 }}>
        <PanelHeader title="Entity Profiling" panelId="profiling_detail" />
        <div className="panel-body" style={{ overflow: 'auto' }}>
          <HostDetailPanel data={scenarioData} />
        </div>
      </Wrapper>
      <Wrapper id="profiling_shap" className="solid-panel" style={{ flex: 2, minHeight: 300 }}>
        <PanelHeader title="Explainability (SHAP & Attention)" panelId="profiling_shap" />
        <div className="panel-body">
          <ExplainabilityPanel
            data={scenarioData.shapValues}
            explainabilityMeta={scenarioData.explainabilityMeta}
          />
        </div>
      </Wrapper>
    </div>
  );

  const renderReconstruction = () => (
    <Wrapper id="reconstruction" className="solid-panel" style={{ minHeight: 500, width: '100%' }}>
      <PanelHeader title="Attack Story Reconstruction" panelId="reconstruction" />
      <div className="panel-body" style={{ padding: 0, flex: 1, minHeight: 0 }}>
        <AttackStoryReconstruction data={scenarioData} />
      </div>
    </Wrapper>
  );

  const renderPipeline = () => (
    <Wrapper id="pipeline" className="solid-panel" style={{ height: '100%', minHeight: 500, width: '100%', display: 'flex', flexDirection: 'column' }}>
      <PanelHeader title="AI Processing Pipeline (Live)" panelId="pipeline" />
      <div className="panel-body" style={{ padding: 0, flex: 1, minHeight: 400, display: 'flex', flexDirection: 'column' }}>
        <PipelineVisualization />
      </div>
    </Wrapper>
  );

  return (
    <ScenarioContext.Provider value={{ currentScenarioKey, setCurrentScenarioKey, scenarios, goHome: () => setAppState('select-dataset'), theme, toggleTheme }}>
      <div className="mesh-bg" />

      <div className="app-layout">
        <Sidebar
          collapsed={sidebarCollapsed}
          onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
          activeView={activeView}
          onViewChange={(view) => { setActiveView(view); setMobileNavOpen(false); }}
          mobileNavOpen={mobileNavOpen}
          setMobileNavOpen={setMobileNavOpen}
          onHome={() => setAppState('setup')}
        />

        <div className="main-area">
          <div className="topbar-wrapper">
            <TopBar data={scenarioData} />
          </div>

        <div className="content-wrapper" style={{ overflowY: 'auto', overflowX: 'hidden' }}>
            {activeView === 'Overview' && renderOverview()}
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
