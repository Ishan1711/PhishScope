import React from 'react';
import type { AuthenticationResults } from '../../types';
import Badge from '../common/Badge';
import './AuthStatusGrid.css';

interface AuthStatusGridProps {
  auth: AuthenticationResults;
}

const AuthStatusGrid: React.FC<AuthStatusGridProps> = ({ auth }) => {
  const getVariant = (status: string) => {
    switch(status.toUpperCase()) {
      case 'PASS': return 'success';
      case 'FAIL': return 'danger';
      case 'SOFTFAIL': return 'warning';
      default: return 'neutral';
    }
  };

  const getBadgeContent = (protocol: string, status: string) => {
    const s = status.toUpperCase();
    let icon = '⚪';
    if (s === 'PASS') icon = '🟢';
    else if (s === 'FAIL') icon = '🔴';
    else if (s === 'SOFTFAIL') icon = '🟡';
    
    return `${icon} ${protocol} ${s}`;
  };

  return (
    <div className="auth-grid card-hover-effect fade-in">
      <div className="auth-item">
        <Badge variant={getVariant(auth.spf)}>{getBadgeContent('SPF', auth.spf)}</Badge>
      </div>
      <div className="auth-item">
        <Badge variant={getVariant(auth.dkim)}>{getBadgeContent('DKIM', auth.dkim)}</Badge>
      </div>
      <div className="auth-item">
        <Badge variant={getVariant(auth.dmarc)}>{getBadgeContent('DMARC', auth.dmarc)}</Badge>
      </div>
    </div>
  );
};

export default AuthStatusGrid;
