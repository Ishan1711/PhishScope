import React from 'react';
import type { RiskScore } from '../../types';
import './ScoreWidget.css';

interface ScoreWidgetProps {
  risk: RiskScore;
}

const ScoreWidget: React.FC<ScoreWidgetProps> = ({ risk }) => {
  const getScoreColor = () => {
    if (risk.threat_level === 'SAFE') return 'var(--success)';
    if (risk.threat_level === 'SUSPICIOUS') return 'var(--warning)';
    return 'var(--danger)';
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (risk.threat_score / 100) * circumference;

  return (
    <div className="score-widget">
      <div className="score-circle-container">
        <svg className="score-svg" viewBox="0 0 100 100">
          <circle 
            className="score-bg" 
            cx="50" cy="50" r="45" 
          />
          <circle 
            className="score-progress" 
            cx="50" cy="50" r="45" 
            stroke={getScoreColor()}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            transform="rotate(-90 50 50)"
          />
        </svg>
        <div className="score-value-container">
          <span className="score-value" style={{ color: getScoreColor() }}>{risk.threat_score}</span>
          <span className="score-label">/100</span>
        </div>
      </div>
      <div className="score-details">
        <h3 className="threat-level" style={{ color: getScoreColor() }}>
          {risk.threat_level.replace('_', ' ')}
        </h3>
        <p className="confidence">Confidence: {risk.confidence_score}%</p>
      </div>
    </div>
  );
};

export default ScoreWidget;
