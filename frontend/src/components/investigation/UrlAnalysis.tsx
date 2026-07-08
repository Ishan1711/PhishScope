import React, { useState } from 'react';
import type { UrlIndicator } from '../../types';
import { Link2, ShieldAlert, ShieldCheck } from 'lucide-react';
import Badge from '../common/Badge';
import './UrlAnalysis.css';

interface UrlAnalysisProps {
  urlIndicators: UrlIndicator[];
}

const getRiskVariant = (risk: string): 'danger' | 'warning' | 'success' => {
  if (risk === 'HIGH') return 'danger';
  if (risk === 'SUSPICIOUS') return 'warning';
  return 'success';
};

const UrlAnalysis: React.FC<UrlAnalysisProps> = ({ urlIndicators }) => {
  const [showAll, setShowAll] = useState(false);

  if (!urlIndicators || urlIndicators.length === 0) {
    return (
      <div className="url-empty">
        <Link2 size={20} color="var(--text-dim)" />
        <p>No URLs found in the email headers.</p>
      </div>
    );
  }

  const threats = urlIndicators.filter(u => u.risk_level !== 'SAFE');
  const safe = urlIndicators.filter(u => u.risk_level === 'SAFE');
  const displayed = showAll ? urlIndicators : urlIndicators.slice(0, 5);

  return (
    <div className="url-analysis">
      <div className="url-summary-row">
        <div className="url-stat">
          <span className="url-stat-val" style={{ color: 'var(--danger)' }}>{threats.length}</span>
          <span className="url-stat-label">Threats</span>
        </div>
        <div className="url-stat">
          <span className="url-stat-val" style={{ color: 'var(--success)' }}>{safe.length}</span>
          <span className="url-stat-label">Clean</span>
        </div>
        <div className="url-stat">
          <span className="url-stat-val">{urlIndicators.length}</span>
          <span className="url-stat-label">Total URLs</span>
        </div>
      </div>

      <div className="url-list">
        {displayed.map((url, idx) => (
          <div key={idx} className={`url-item url-risk-${url.risk_level.toLowerCase()}`}>
            <div className="url-item-top">
              <div className="url-item-icon">
                {url.risk_level === 'SAFE'
                  ? <ShieldCheck size={13} color="var(--success)" />
                  : <ShieldAlert size={13} color={url.risk_level === 'HIGH' ? 'var(--danger)' : 'var(--warning)'} />
                }
              </div>
              <div className="url-item-info">
                <div className="url-item-domain">
                  <span className="font-mono text-sm">{url.domain || url.url.slice(0, 50)}</span>
                  <Badge variant={getRiskVariant(url.risk_level)}>{url.risk_level}</Badge>
                </div>
                <div className="url-item-full" title={url.url}>{url.url.slice(0, 80)}{url.url.length > 80 ? '…' : ''}</div>
              </div>
            </div>
            {url.reasons.length > 0 && (
              <div className="url-reasons">
                {url.reasons.map((r, i) => (
                  <span key={i} className="url-reason-chip">{r}</span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {urlIndicators.length > 5 && (
        <button className="url-show-more" onClick={() => setShowAll(!showAll)}>
          {showAll ? 'Show less' : `Show ${urlIndicators.length - 5} more URLs`}
        </button>
      )}
    </div>
  );
};

export default UrlAnalysis;
