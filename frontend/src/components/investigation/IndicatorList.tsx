import React from 'react';
import type { Indicator } from '../../types';
import Badge from '../common/Badge';
import { AlertTriangle, Info } from 'lucide-react';
import './IndicatorList.css';

interface IndicatorListProps {
  indicators: Indicator[];
}

const IndicatorList: React.FC<IndicatorListProps> = ({ indicators }) => {
  if (!indicators || indicators.length === 0) {
    return (
      <div className="no-indicators">
        <Info size={24} color="var(--text-muted)" />
        <p>No suspicious indicators found.</p>
      </div>
    );
  }

  return (
    <div className="indicator-list">
      {indicators.map((ind, idx) => (
        <div key={idx} className={`indicator-item severity-${ind.severity.toLowerCase()}`}>
          <div className="indicator-icon">
            <AlertTriangle size={20} />
          </div>
          <div className="indicator-content">
            <div className="indicator-header">
              <span className="indicator-name">{ind.name}</span>
              <Badge variant={
                ind.severity === 'HIGH' ? 'danger' : 
                ind.severity === 'MEDIUM' ? 'warning' : 'neutral'
              }>
                {ind.severity}
              </Badge>
            </div>
            <p className="indicator-desc">{ind.description}</p>
          </div>
        </div>
      ))}
    </div>
  );
};

export default IndicatorList;
