import { Paperclip } from 'lucide-react';
import { narrativeEntries } from '../data/mockAttackScenario';

export default function NarrativePanel() {
  return (
    <div>
      {narrativeEntries.map((entry, i) => (
        <div key={i} className={`narrative-entry ${entry.type}`}>
          <div className={`narrative-tag ${entry.type}`}>
            {entry.type === 'confirmed' ? '✓ CONFIRMED' :
             entry.type === 'predicted' ? '⚡ PREDICTED' : '🎯 ACTION'}
          </div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-tertiary)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
            {entry.timestamp}
          </div>
          <div className="narrative-text">{entry.text}</div>
          {entry.evidence && (
            <div className="narrative-evidence">
              <Paperclip size={12} style={{ flexShrink: 0 }} />
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.evidence}</span>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
