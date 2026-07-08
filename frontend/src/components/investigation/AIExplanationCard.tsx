import React from 'react';
import { Bot, Sparkles } from 'lucide-react';
import './AIExplanationCard.css';

interface AIExplanationCardProps {
  explanation?: string;
  isLoading?: boolean; // Added isLoading prop
}

const AIExplanationCard: React.FC<AIExplanationCardProps> = ({ explanation, isLoading }) => {
  if (!explanation && !isLoading) {
    return null; // or could render skeleton by default if expected
  }

  return (
    <div className="ai-card card-hover-effect fade-in">
      <div className="ai-card-header">
        <Bot size={18} className="ai-icon" />
        <span className="ai-title">Groq AI Executive Summary</span>
        <Sparkles size={14} className="ai-sparkle" />
      </div>
      <div className="ai-card-body">
        {isLoading || !explanation ? (
          <div className="ai-skeleton-container">
            <div className="skeleton skeleton-line" style={{ width: '100%' }}></div>
            <div className="skeleton skeleton-line" style={{ width: '92%' }}></div>
            <div className="skeleton skeleton-line" style={{ width: '96%' }}></div>
          </div>
        ) : (
          <p className="ai-text">{explanation}</p>
        )}
      </div>
    </div>
  );
};

export default AIExplanationCard;
