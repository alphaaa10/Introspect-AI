import { ShieldOff, Eye, CheckCircle, ArrowUpRight, Download } from 'lucide-react';

export default function AnalystActions() {
  return (
    <div className="analyst-actions">
      <button className="action-btn isolate">
        <ShieldOff size={12} />
        Isolate Host
      </button>
      <button className="action-btn monitor">
        <Eye size={12} />
        Increase Monitoring
      </button>
      <button className="action-btn dismiss">
        <CheckCircle size={12} />
        Dismiss
      </button>
      <button className="action-btn escalate">
        <ArrowUpRight size={12} />
        Escalate to Tier 2
      </button>
      <button className="action-btn export">
        <Download size={12} />
        Export Report
      </button>
    </div>
  );
}
