import React, { useMemo, useCallback } from 'react';
import type { RiskScore } from '../../types';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
import './ScoreWidget.css';

ChartJS.register(ArcElement, Tooltip, Legend);

interface ScoreWidgetProps {
  risk: RiskScore;
}

const ScoreWidget: React.FC<ScoreWidgetProps> = ({ risk }) => {
  const getScoreColor = useCallback(() => {
    if (risk.threat_level === 'HIGHLY SUSPICIOUS') return '#EF4444'; // danger
    if (risk.threat_level === 'SUSPICIOUS') return '#F59E0B'; // warning
    return '#10B981'; // success
  }, [risk.threat_level]);

  const chartData = useMemo(() => {
    const value = risk.threat_score;
    const remainder = 100 - value;
    
    return {
      datasets: [
        {
          data: [value, remainder],
          backgroundColor: [getScoreColor(), 'rgba(255, 255, 255, 0.05)'], // border-color for empty part
          borderWidth: 0,
          circumference: 180,
          rotation: 270,
        },
      ],
    };
  }, [risk.threat_score, getScoreColor]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '80%',
    plugins: {
      tooltip: { enabled: false },
      legend: { display: false },
    },
  };

  return (
    <div className="score-widget fade-in">
      <div className="score-gauge-container">
        <Doughnut data={chartData} options={chartOptions} />
        <div className="score-value-container">
          <span className="score-value" style={{ color: getScoreColor() }}>
            {risk.threat_score}
          </span>
          <span className="score-label">/100</span>
        </div>
      </div>
      
      <div className="score-details">
        <div className="threat-level" style={{ color: getScoreColor() }}>
          {risk.threat_level}
        </div>
        <div className="confidence">
          Confidence: {risk.confidence_score}%
        </div>
      </div>
    </div>
  );
};

export default ScoreWidget;
