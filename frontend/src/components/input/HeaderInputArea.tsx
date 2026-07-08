import React from 'react';
import './HeaderInputArea.css';

interface HeaderInputAreaProps {
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
}

const HeaderInputArea: React.FC<HeaderInputAreaProps> = ({ value, onChange, placeholder = 'Paste email headers here...' }) => {
  return (
    <textarea 
      className="header-textarea"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      spellCheck={false}
    />
  );
};

export default HeaderInputArea;
