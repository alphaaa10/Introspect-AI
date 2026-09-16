import {
  Activity,
  Network,
  Radar,
  ShieldAlert,
  BookOpen,
  PanelLeftClose,
  PanelLeftOpen,
  Cpu,
  LayoutDashboard,
  TrendingUp,
  Menu,
  X,
  Search
} from 'lucide-react';

import { useState } from 'react';

const mainNavItems = [
  { icon: LayoutDashboard, label: 'Overview', id: 'Overview' },
  { icon: TrendingUp, label: 'Forecast', id: 'Forecast' },
  { icon: Network, label: 'Topology', id: 'Topology' },
  { icon: Radar, label: 'Detections', id: 'Detections' },
  { icon: ShieldAlert, label: 'Profiling', id: 'Profiling' },
  { icon: BookOpen, label: 'Story Reconstruction', id: 'Reconstruction' },
  { icon: Cpu, label: 'AI Pipeline', id: 'Pipeline' },
];

export default function Sidebar({ collapsed, onToggle, activeView, onViewChange, mobileNavOpen, setMobileNavOpen, onHome }) {
  const [showOfflineToast, setShowOfflineToast] = useState(false);

  const handleSearchClick = () => {
    setShowOfflineToast(true);
    setTimeout(() => setShowOfflineToast(false), 3000);
  };

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''} ${mobileNavOpen ? 'mobile-open' : ''}`}>
      {showOfflineToast && (
        <div className="offline-toast">
          <Search size={14} />
          Search is unavailable in offline / simulation view
        </div>
      )}
      
      <div className="sidebar-header">
        <a href="#" className="sidebar-logo" onClick={(e) => { e.preventDefault(); onHome?.(); }}>
          <div className="sidebar-logo-icon">
            <Cpu size={18} />
          </div>
          <span className="sidebar-logo-text">Introspect AI</span>
        </a>
        <button className="sidebar-toggle-btn desktop-only" onClick={onToggle} title={collapsed ? 'Expand' : 'Collapse'}>
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
        <div className="mobile-header-actions">
          <button className="mobile-search-btn" onClick={handleSearchClick} title="Search">
            <Search size={18} />
          </button>
          <button className="mobile-menu-btn" onClick={() => setMobileNavOpen(!mobileNavOpen)}>
            {mobileNavOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      <nav className="sidebar-nav">
        {mainNavItems.map((item) => (
          <div
            key={item.id}
            className={`sidebar-item ${activeView === item.id ? 'active' : ''}`}
            onClick={() => onViewChange(item.id)}
            title={collapsed ? item.label : undefined}
          >
            <item.icon size={18} strokeWidth={activeView === item.id ? 2.5 : 2} />
            <span>{item.label}</span>
          </div>
        ))}
      </nav>
    </aside>
  );
}
