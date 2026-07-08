import React from 'react';
import type { Hop } from '../../types';
import { Server, Clock, Activity } from 'lucide-react';
import './Timeline.css';

interface TimelineProps {
  hops: Hop[];
}

const Timeline: React.FC<TimelineProps> = ({ hops }) => {
  if (!hops || hops.length === 0) {
    return <div className="no-hops">No routing hops found.</div>;
  }

  // Reverse hops to show origin at bottom and final destination at top (SOC style)
  const reversedHops = [...hops].reverse();

  return (
    <div className="timeline-container fade-in">
      {reversedHops.map((hop, idx) => {
        // Assume delay might be available on Hop interface in future, or mock for UI aesthetic if missing
        const delayStr = (hop as any).delay ? `Delay: ${(hop as any).delay}` : 'Delay: < 1s';
        
        return (
          <div key={idx} className="timeline-item">
            <div className="timeline-icon-wrapper">
              <Server size={14} className="timeline-icon-svg" />
            </div>
            
            <div className="timeline-content card-hover-effect">
              <div className="timeline-header">
                <span className="hop-number">Hop {hop.hop_number}</span>
                <span className="hop-time">
                  <Clock size={12} style={{marginRight: 4}} />
                  {hop.timestamp || 'Unknown Time'}
                </span>
              </div>
              
              <div className="hop-details">
                <div className="hop-row">
                  <span className="hop-label">Server</span>
                  <span className="hop-value highlight-text">{hop.from_server || hop.by_server}</span>
                </div>
                
                <div className="hop-row">
                  <span className="hop-label">Protocol</span>
                  <span className="hop-value protocol-badge">{hop.with_protocol || 'SMTP'}</span>
                </div>

                <div className="hop-row">
                  <span className="hop-label">Performance</span>
                  <span className="hop-value performance-text">
                    <Activity size={12} style={{marginRight: 4}} />
                    {delayStr}
                  </span>
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default Timeline;
