import { 
  Activity, 
  Network, 
  Radar, 
  ShieldAlert, 
  BookOpen,
  Settings, 
  LogOut, 
  PanelLeftClose, 
  PanelLeftOpen,
  Cpu,
  LayoutDashboard,
  TrendingUp
} from 'lucide-react';

const mainNavItems = [
  { icon: LayoutDashboard, label: 'Overview', id: 'Overview' },
  { icon: TrendingUp, label: 'Forecast', id: 'Forecast' },
  { icon: Network, label: 'Topology', id: 'Topology' },
  { icon: Radar, label: 'Detections', id: 'Detections' },
  { icon: ShieldAlert, label: 'Profiling', id: 'Profiling' },
  { icon: BookOpen, label: 'Story Reconstruction', id: 'Reconstruction' },
  { icon: Cpu, label: 'AI Pipeline', id: 'Pipeline' },
];

export default function Sidebar({ collapsed, onToggle, activeView, onViewChange }) {
  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <a href="#" className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <Cpu size={20} />
          </div>
          <span className="sidebar-logo-text">Introspect AI</span>
        </a>
        <button className="sidebar-toggle-btn" onClick={onToggle}>
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
      </div>

      <nav className="sidebar-nav">
        {mainNavItems.map((item) => (
          <div
            key={item.id}
            className={`sidebar-item ${activeView === item.id ? 'active' : ''}`}
            onClick={() => onViewChange(item.id)}
            title={collapsed ? item.label : undefined}
          >
            <item.icon size={20} strokeWidth={activeView === item.id ? 2.5 : 2} />
            <span>{item.label}</span>
          </div>
        ))}
      </nav>

      <div style={{ padding: 'var(--space-4) 0', borderTop: '1px solid var(--surface-divider)' }}>
        <div className="sidebar-item" title={collapsed ? "Settings" : undefined}>
          <Settings size={20} />
          <span>Settings</span>
        </div>
        <div className="sidebar-item" title={collapsed ? "Log Out" : undefined} style={{ color: 'var(--severity-critical)' }}>
          <LogOut size={20} />
          <span>Log Out</span>
        </div>
      </div>
    </aside>
  );
}
