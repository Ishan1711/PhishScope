import React from 'react';
import type { AuthenticationResults } from '../../types';
import Badge from '../common/Badge';
import './AuthStatusGrid.css';

interface AuthStatusGridProps {
  auth: AuthenticationResults;
}

const AuthStatusGrid: React.FC<AuthStatusGridProps> = ({ auth }) => {
  const getVariant = (status: string) => {
    switch(status) {
      case 'PASS': return 'success';
      case 'FAIL': return 'danger';
      case 'SOFTFAIL': return 'warning';
      default: return 'neutral';
    }
  };

  return (
    <div className="auth-grid">
      <div className="auth-item">
        <span className="auth-label">SPF</span>
        <Badge variant={getVariant(auth.spf)}>{auth.spf}</Badge>
      </div>
      <div className="auth-item">
        <span className="auth-label">DKIM</span>
        <Badge variant={getVariant(auth.dkim)}>{auth.dkim}</Badge>
      </div>
      <div className="auth-item">
        <span className="auth-label">DMARC</span>
        <Badge variant={getVariant(auth.dmarc)}>{auth.dmarc}</Badge>
      </div>
    </div>
  );
};

export default AuthStatusGrid;
