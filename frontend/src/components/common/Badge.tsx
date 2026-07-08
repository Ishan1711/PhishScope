import React from 'react';
import './Badge.css';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'success' | 'warning' | 'danger' | 'neutral';
}

const Badge: React.FC<BadgeProps> = ({ children, variant = 'neutral' }) => {
  return (
    <span className={`custom-badge badge-${variant}`}>
      {children}
    </span>
  );
};

export default Badge;
