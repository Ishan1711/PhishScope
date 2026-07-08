import React, { useMemo } from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import type { RiskScore } from '../../types';
import './ScoreWidget.css';

ChartJS.register(ArcElement, Tooltip, Legend);

interface ScoreWidgetProps {
  risk: RiskScore;
}

const ScoreWidget: React.FC<ScoreWidgetProps> = ({ risk }) => {
  const getScoreColor = () => {
    if (risk.threat_level === 'SAFE') return '#10B981'; // success
    if (risk.threat_level === 'SUSPICIOUS') return '#F59E0B'; // warning
    return '#EF4444'; // danger
  };

  const chartData = useMemo(() => {
    const value = risk.threat_score;
    const remainder = 100 - value;
    return {
      labels: ['Threat', 'Safe'],
      datasets: [
        {
          data: [value, remainder],
          backgroundColor: [getScoreColor(), '#27272a'], // border-color for empty part
          borderWidth: 0,
          circumference: 180,
          rotation: 270,
        },
      ],
    };
  }, [risk.threat_score, risk.threat_level]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '80%',
    plugins: {
      legend: { display: false },
      tooltip: { enabled: false },
    },
    animation: {
      animateRotate: true,
      animateScale: false,
      duration: 1500,
      easing: 'easeOutQuart' as const,
    },
  };

  return (
    <div className="score-widget card-hover-effect">
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
        <h3 className="threat-level" style={{ color: getScoreColor() }}>
          {risk.threat_level.replace('_', ' ')}
        </h3>
        <p className="confidence">Confidence: {risk.confidence_score}%</p>
      </div>
    </div>
  );
};

export default ScoreWidget;

