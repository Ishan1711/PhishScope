import React from 'react';
import { ShieldCheck } from 'lucide-react';
import './Header.css';

const Header: React.FC = () => {
  return (
    <header className="app-header">
      <div className="logo-container">
        <ShieldCheck size={28} color="var(--primary)" />
        <span className="logo-text">PhishScope</span>
      </div>
    </header>
  );
};

export default Header;
