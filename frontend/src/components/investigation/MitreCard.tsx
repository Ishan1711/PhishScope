import React from 'react';
import type { MitreTechnique } from '../../types';
import { ExternalLink } from 'lucide-react';
import './MitreCard.css';

interface MitreCardProps {
  techniques: MitreTechnique[];
}

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access': 'var(--danger)',
  'Defense Evasion': 'var(--warning)',
  'Command and Control': 'var(--info)',
  'Execution': 'var(--danger)',
  'Persistence': 'var(--warning)',
  'Collection': 'var(--primary)',
};

const MitreCard: React.FC<MitreCardProps> = ({ techniques }) => {
  if (!techniques || techniques.length === 0) return null;

  return (
    <div className="mitre-card">
      <div className="mitre-list">
        {techniques.map((t, idx) => {
          const color = TACTIC_COLORS[t.tactic] || 'var(--primary)';
          return (
            <div key={idx} className="mitre-item">
              <div className="mitre-item-top">
                <a
                  href={t.url || `https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mitre-id"
                  style={{ color }}
                >
                  {t.technique_id}
                  <ExternalLink size={9} />
                </a>
                <span className="mitre-tactic">
                  {t.tactic}
                </span>
              </div>
              <div className="mitre-technique-name">{t.technique_name}</div>
              {t.description && (
                <div className="mitre-description">{t.description}</div>
              )}
            </div>
          );
        })}
      </div>
      <div className="mitre-footer">
        MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation.
      </div>
    </div>
  );
};

export default MitreCard;
