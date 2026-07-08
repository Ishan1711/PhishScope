import React from 'react';
import type { AuthenticationResults } from '../../types';
import { ShieldCheck, ShieldAlert, ShieldX, HelpCircle } from 'lucide-react';
import './AuthStatusGrid.css';

interface AuthStatusGridProps {
  auth: AuthenticationResults;
}

const AuthStatusGrid: React.FC<AuthStatusGridProps> = ({ auth }) => {
  const getStatusConfig = (status: string) => {
    const s = status.toUpperCase();
    switch(s) {
      case 'PASS': 
        return { variant: 'pass', icon: <ShieldCheck size={16} />, label: 'PASS' };
      case 'FAIL': 
        return { variant: 'fail', icon: <ShieldX size={16} />, label: 'FAIL' };
      case 'SOFTFAIL': 
      case 'TEMPERROR':
        return { variant: 'softfail', icon: <ShieldAlert size={16} />, label: s };
      default: 
        return { variant: 'neutral', icon: <HelpCircle size={16} />, label: s || 'NONE' };
    }
  };

  const renderAuthItem = (protocol: string, status: string, detail?: string) => {
    const config = getStatusConfig(status);
    return (
      <div className="auth-item">
        <div className="auth-protocol">{protocol}</div>
        <div className={`auth-status ${config.variant}`}>
          {config.icon} {config.label}
        </div>
        {detail && (
          <div className="auth-detail-tooltip">
            {detail}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="auth-grid fade-in">
      {renderAuthItem('SPF', auth.spf, auth.spf_domain ? `Domain: ${auth.spf_domain}` : 'No SPF domain provided')}
      {renderAuthItem('DKIM', auth.dkim, auth.dkim_domain ? `d=${auth.dkim_domain}${auth.dkim_selector ? ` s=${auth.dkim_selector}` : ''}` : 'No DKIM signature found')}
      {renderAuthItem('DMARC', auth.dmarc, auth.dmarc_policy ? `policy=${auth.dmarc_policy}` : 'No DMARC policy found')}
    </div>
  );
};

export default AuthStatusGrid;
