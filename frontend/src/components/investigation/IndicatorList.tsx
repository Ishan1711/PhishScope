import React, { useState } from 'react';
import type { Indicator } from '../../types';
import Badge from '../common/Badge';
import { AlertTriangle, Info, ChevronDown, ChevronUp } from 'lucide-react';
import './IndicatorList.css';

interface IndicatorListProps {
  indicators: Indicator[];
}

const IndicatorList: React.FC<IndicatorListProps> = ({ indicators }) => {
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  if (!indicators || indicators.length === 0) {
    return (
      <div className="no-indicators">
        <Info size={24} color="var(--text-muted)" />
        <p>No suspicious indicators found.</p>
      </div>
    );
  }

  const toggleExpand = (idx: number) => {
    setExpandedIdx(expandedIdx === idx ? null : idx);
  };

  return (
    <div className="indicator-list fade-in">
      {indicators.map((ind, idx) => {
        const isExpanded = expandedIdx === idx;
        return (
          <div 
            key={idx} 
            className={`indicator-item severity-${ind.severity.toLowerCase()} ${isExpanded ? 'expanded' : ''}`}
            onClick={() => toggleExpand(idx)}
          >
            <div className="indicator-icon">
              <AlertTriangle size={18} />
            </div>
            <div className="indicator-content">
              <div className="indicator-header">
                <span className="indicator-name">{ind.name}</span>
                <div className="indicator-header-right">
                  <Badge variant={
                    ind.severity === 'HIGH' ? 'danger' : 
                    ind.severity === 'MEDIUM' ? 'warning' : 'neutral'
                  }>
                    {ind.severity}
                  </Badge>
                  <button className="expand-btn">
                    {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </button>
                </div>
              </div>
              
              <p className="indicator-desc-preview">{ind.description}</p>

              {isExpanded && (
                <div className="indicator-expanded-details">
                  <div className="detail-row">
                    <span className="detail-label">Category:</span>
                    <span className="detail-value">{ind.category || 'Threat Intelligence'}</span>
                  </div>
                  <div className="detail-row">
                    <span className="detail-label">Score Impact:</span>
                    <span className="detail-value">+{ind.score_contribution || 0} pts</span>
                  </div>
                  <div className="detail-row full-width">
                    <span className="detail-label">Details:</span>
                    <span className="detail-value">{ind.description}</span>
                  </div>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default IndicatorList;
