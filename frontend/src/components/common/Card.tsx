import React, { ReactNode } from 'react';
import './Card.css';

interface CardProps {
  title?: ReactNode;
  children: ReactNode;
  className?: string;
  headerAction?: ReactNode;
}

const Card: React.FC<CardProps> = ({ title, children, className = '', headerAction }) => {
  return (
    <div className={`custom-card card-hover-effect ${className}`}>
      {title && (
        <div className="card-header">
          <h2 className="card-title">{title}</h2>
          {headerAction && <div className="card-action">{headerAction}</div>}
        </div>
      )}
      <div className="card-body">
        {children}
      </div>
    </div>
  );
};

export default Card;
