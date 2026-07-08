import React from 'react';
import { Bot, Sparkles } from 'lucide-react';
import './AIExplanationCard.css';

interface AIExplanationCardProps {
  explanation?: string;
  isLoading?: boolean;
}

const AIExplanationCard: React.FC<AIExplanationCardProps> = ({ explanation, isLoading }) => {
  if (!explanation && !isLoading) {
    return null;
  }

  // Parse sections based on "## " markdown headers
  const renderContent = () => {
    if (!explanation) return null;
    
    const sections = explanation.split('## ').filter(Boolean);
    
    if (sections.length <= 1) {
      // Fallback if no headers found
      return <p className="ai-text">{explanation}</p>;
    }

    return (
      <div className="ai-sections">
        {sections.map((section, idx) => {
          const firstNewline = section.indexOf('\n');
          if (firstNewline === -1) return null;
          
          const title = section.slice(0, firstNewline).trim();
          const content = section.slice(firstNewline + 1).trim();
          
          if (!title || !content) return null;
          
          return (
            <div key={idx} className="ai-section fade-in" style={{animationDelay: `${idx * 0.1}s`}}>
              <h3 className="ai-section-title">{title}</h3>
              <div className="ai-section-content">
                {content.split('\n').map((line, i) => {
                  const tLine = line.trim();
                  if (!tLine) return <br key={i} />;
                  if (tLine.startsWith('- ') || tLine.startsWith('* ')) {
                    return <li key={i} className="ai-list-item">{tLine.substring(2)}</li>;
                  }
                  return <p key={i} className="ai-paragraph">{tLine}</p>;
                })}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="ai-card card-hover-effect fade-in">
      <div className="ai-card-header">
        <div className="ai-header-left">
          <Bot size={20} className="ai-icon" />
          <span className="ai-title">Groq AI Executive Summary</span>
        </div>
        <Sparkles size={16} className="ai-sparkle" />
      </div>
      <div className="ai-card-body">
        {isLoading || !explanation ? (
          <div className="ai-skeleton-container">
            <div className="skeleton skeleton-line" style={{ width: '100%' }}></div>
            <div className="skeleton skeleton-line" style={{ width: '92%' }}></div>
            <div className="skeleton skeleton-line" style={{ width: '96%' }}></div>
          </div>
        ) : (
          renderContent()
        )}
      </div>
    </div>
  );
};

export default AIExplanationCard;
