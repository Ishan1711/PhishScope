import React from 'react';
import { Bot } from 'lucide-react';
import './AIExplanationCard.css';

interface AIExplanationCardProps {
  explanation?: string;
}

const AIExplanationCard: React.FC<AIExplanationCardProps> = ({ explanation }) => {
  if (!explanation) {
    return null;
  }

  return (
    <div className="ai-card">
      <div className="ai-card-header">
        <Bot size={20} className="ai-icon" />
        <span className="ai-title">AI Executive Summary</span>
      </div>
      <div className="ai-card-body">
        <p className="ai-text">{explanation}</p>
      </div>
    </div>
  );
};

export default AIExplanationCard;
