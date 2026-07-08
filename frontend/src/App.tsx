import React, { useState, useEffect } from 'react';
import LandingPage from './pages/LandingPage';
import InvestigationDashboard from './pages/InvestigationDashboard';
import type { AnalysisResult } from './types';
import './index.css';

function App() {
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);

  // Attempt to load from local storage on mount
  useEffect(() => {
    const saved = localStorage.getItem('phishscope_recent_analysis');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.investigation_id) {
          setCurrentResult(parsed);
        }
      } catch (e) {
        console.error("Failed to parse saved analysis");
      }
    }
  }, []);

  const handleAnalysisComplete = (result: AnalysisResult) => {
    setCurrentResult(result);
    localStorage.setItem('phishscope_recent_analysis', JSON.stringify(result));
  };

  const handleNewAnalysis = () => {
    setCurrentResult(null);
  };

  return (
    <div className="app-container">
      {currentResult ? (
        <InvestigationDashboard result={currentResult} onNewAnalysis={handleNewAnalysis} />
      ) : (
        <LandingPage onAnalysisComplete={handleAnalysisComplete} />
      )}
    </div>
  );
}

export default App;
