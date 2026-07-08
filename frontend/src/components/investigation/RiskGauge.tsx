import React from 'react';
import type { RiskScore } from '../../types';
import './RiskGauge.css';

interface RiskGaugeProps {
  risk: RiskScore;
}

const RiskGauge: React.FC<RiskGaugeProps> = ({ risk }) => {
  const { threat_score, threat_level, confidence_score } = risk;

  const getColor = () => {
    if (threat_level === 'SAFE') return 'var(--success)';
    if (threat_level === 'SUSPICIOUS') return 'var(--warning)';
    return 'var(--danger)';
  };
  const color = getColor();

  return (
    <div className="risk-gauge">
      <div className="risk-header">
        <div className="risk-score-display">
          <span className="risk-score-val" style={{ color }}>{threat_score}</span>
          <span className="risk-score-max">/ 100</span>
        </div>
        <div className="risk-level-badge" style={{ color: color, borderColor: color }}>
          {threat_level}
        </div>
      </div>

      <div className="risk-bar-container">
        <div className="risk-bar-track">
          <div
            className="risk-bar-fill"
            style={{ 
              width: `${Math.max(2, threat_score)}%`, 
              backgroundColor: color 
            }}
          />
        </div>
        <div className="risk-bar-markers">
          <span>SAFE (0-30)</span>
          <span>SUSPICIOUS (31-60)</span>
          <span>CRITICAL (61-100)</span>
        </div>
      </div>

      <div className="risk-footer">
        <span>Analysis Confidence</span>
        <span className="risk-confidence">{confidence_score}%</span>
      </div>
    </div>
  );
};

export default RiskGauge;
