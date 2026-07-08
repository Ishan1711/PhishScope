import React from 'react';
import type { ScoreItem } from '../../types';
import './ScoreBreakdown.css';

interface ScoreBreakdownProps {
  breakdown: ScoreItem[];
  totalScore: number;
}

const categoryColors: Record<string, string> = {
  Authentication: 'var(--info)',
  Header: 'var(--warning)',
  Domain: 'var(--danger)',
  Spoofing: 'var(--danger)',
  Routing: 'var(--warning)',
  URL: 'var(--danger)',
  General: 'var(--text-muted)',
};

const ScoreBreakdown: React.FC<ScoreBreakdownProps> = ({ breakdown, totalScore }) => {
  const safeBreakdown = breakdown ?? [];

  if (safeBreakdown.length === 0) {
    return (
      <div className="score-breakdown-empty">
        <p>No risk factors detected.</p>
      </div>
    );
  }

  const sorted = [...safeBreakdown]
    .filter(item => item && typeof item.points === 'number')
    .sort((a, b) => (b.points ?? 0) - (a.points ?? 0));

  return (
    <div className="score-breakdown">
      <div className="breakdown-list">
        {sorted.map((item, idx) => {
          const catColor = categoryColors[item.category] || 'var(--text-muted)';
          return (
            <div key={idx} className="breakdown-item">
              <div className="breakdown-item-left">
                <span className="breakdown-points" style={{ color: catColor }}>
                  +{item.points}
                </span>
                <span className="breakdown-reason">{item.reason}</span>
              </div>
              <span className="breakdown-category">
                {item.category}
              </span>
            </div>
          );
        })}
      </div>
      <div className="breakdown-total">
        <span className="breakdown-total-label">Total Risk Score</span>
        <span className="breakdown-total-value">
          {totalScore ?? 0}
          <span className="breakdown-total-max">/100</span>
        </span>
      </div>
    </div>
  );
};

export default ScoreBreakdown;
