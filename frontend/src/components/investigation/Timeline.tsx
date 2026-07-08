import React from 'react';
import type { Hop } from '../../types';
import { Server } from 'lucide-react';
import './Timeline.css';

interface TimelineProps {
  hops: Hop[];
}

const Timeline: React.FC<TimelineProps> = ({ hops }) => {
  if (!hops || hops.length === 0) {
    return <div className="no-hops">No routing hops found.</div>;
  }

  return (
    <div className="timeline-container">
      {hops.map((hop, idx) => (
        <div key={idx} className="timeline-item">
          <div className="timeline-icon">
            <Server size={16} />
          </div>
          <div className="timeline-content">
            <div className="timeline-header">
              <span className="hop-number">Hop {hop.hop_number}</span>
              <span className="hop-time">{hop.timestamp}</span>
            </div>
            <div className="hop-details">
              <div className="hop-row">
                <span className="hop-label">From:</span>
                <span className="hop-value">{hop.from_server}</span>
              </div>
              <div className="hop-row">
                <span className="hop-label">By:</span>
                <span className="hop-value">{hop.by_server}</span>
              </div>
              <div className="hop-row">
                <span className="hop-label">Protocol:</span>
                <span className="hop-value">{hop.with_protocol}</span>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default Timeline;
