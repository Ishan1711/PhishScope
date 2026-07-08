import React from 'react';
import { Copy, Info } from 'lucide-react';
import './FieldViewer.css';

interface FieldViewerProps {
  fields: { label: string; value: string }[];
}

const FieldViewer: React.FC<FieldViewerProps> = ({ fields }) => {
  const handleCopy = (text: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
  };

  const renderFieldValue = (field: { label: string; value: string }) => {
    if (field.label === 'Originating IP' && (!field.value || field.value === 'N/A')) {
      return (
        <span 
          className="hidden-ip-badge" 
          title="The originating IP address is intentionally hidden by the email provider for privacy and security."
        >
          Hidden by Email Provider <Info size={14} className="info-icon" />
        </span>
      );
    }
    
    return (
      <>
        <span className="field-value">{field.value || 'N/A'}</span>
        {field.value && (
          <button 
            className="copy-btn" 
            onClick={() => handleCopy(field.value)}
            title="Copy to clipboard"
          >
            <Copy size={14} />
          </button>
        )}
      </>
    );
  };

  return (
    <div className="field-viewer card-hover-effect fade-in">
      {fields.map((field, idx) => (
        <div key={idx} className="field-row">
          <div className="field-label">{field.label}</div>
          <div className="field-value-container">
            {renderFieldValue(field)}
          </div>
        </div>
      ))}
    </div>
  );
};

export default FieldViewer;
