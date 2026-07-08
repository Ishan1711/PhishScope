import React from 'react';
import type { IocSummary as IocSummaryType } from '../../types';
import { AlertTriangle, AlertOctagon, Info, Link2, Shield, UserX } from 'lucide-react';
import './IocSummaryWidget.css';

interface IocSummaryWidgetProps {
  ioc: IocSummaryType;
}

const IocSummaryWidget: React.FC<IocSummaryWidgetProps> = ({ ioc }) => {
  const highCount = ioc?.high_count ?? 0;
  const mediumCount = ioc?.medium_count ?? 0;
  const lowCount = ioc?.low_count ?? 0;
  const total = ioc?.total ?? 0;
  const urlThreats = ioc?.url_threats ?? 0;
  const authFailures = ioc?.auth_failures ?? 0;
  const spoofingDetected = ioc?.spoofing_detected ?? false;
  const domainSuspicious = ioc?.domain_suspicious ?? false;

  const stats = [
    {
      label: 'High',
      value: highCount,
      icon: <AlertOctagon size={12} aria-hidden="true" />,
      color: 'var(--danger)',
    },
    {
      label: 'Medium',
      value: mediumCount,
      icon: <AlertTriangle size={12} aria-hidden="true" />,
      color: 'var(--warning)',
    },
    {
      label: 'Low',
      value: lowCount,
      icon: <Info size={12} aria-hidden="true" />,
      color: 'var(--info)',
    },
  ];

  const flags = [
    {
      label: 'Spoofing',
      active: spoofingDetected,
      icon: <UserX size={12} aria-hidden="true" />,
      color: 'var(--danger)',
      value: undefined,
    },
    {
      label: 'Suspicious Domain',
      active: domainSuspicious,
      icon: <Shield size={12} aria-hidden="true" />,
      color: 'var(--warning)',
      value: undefined,
    },
    {
      label: 'URL Threats',
      active: urlThreats > 0,
      icon: <Link2 size={12} aria-hidden="true" />,
      color: 'var(--warning)',
      value: urlThreats,
    },
    {
      label: 'Auth Failures',
      active: authFailures > 0,
      icon: <AlertOctagon size={12} aria-hidden="true" />,
      color: 'var(--danger)',
      value: authFailures,
    },
  ].filter(f => f.active);

  return (
    <div className="ioc-summary-widget">
      <div className="ioc-metrics" role="region" aria-label="IOC severity counts">
        {stats.map(stat => (
          <div key={stat.label} className="ioc-metric">
            <div className="ioc-metric-header" style={{ color: stat.color }}>
              {stat.icon}
              <span>{stat.label}</span>
            </div>
            <div className="ioc-metric-value">{stat.value}</div>
          </div>
        ))}
      </div>

      {flags.length > 0 && (
        <div className="ioc-flags-list" role="list" aria-label="Active threat flags">
          {flags.map(flag => (
            <div
              key={flag.label}
              className="ioc-flag-item"
              role="listitem"
            >
              <span className="ioc-flag-icon" style={{ color: flag.color }}>{flag.icon}</span>
              <span className="ioc-flag-label">{flag.label}</span>
              {flag.value !== undefined && <span className="ioc-flag-count">{flag.value}</span>}
            </div>
          ))}
        </div>
      )}

      {total === 0 && (
        <div className="ioc-clean" role="status">
          <Shield size={14} color="var(--success)" aria-hidden="true" />
          <span>No indicators of compromise detected</span>
        </div>
      )}
    </div>
  );
};

export default IocSummaryWidget;
