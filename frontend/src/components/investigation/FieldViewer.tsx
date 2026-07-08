import React from 'react';
import { Copy } from 'lucide-react';
import './FieldViewer.css';

interface FieldViewerProps {
  fields: { label: string; value: string }[];
}

const FieldViewer: React.FC<FieldViewerProps> = ({ fields }) => {
  const handleCopy = (text: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    // Could add a toast notification here
  };

  return (
    <div className="field-viewer">
      {fields.map((field, idx) => (
        <div key={idx} className="field-row">
          <div className="field-label">{field.label}</div>
          <div className="field-value-container">
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
          </div>
        </div>
      ))}
    </div>
  );
};

export default FieldViewer;
