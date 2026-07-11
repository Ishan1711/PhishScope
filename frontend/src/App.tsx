import React, { useState } from 'react';
import LandingPage from './pages/LandingPage';
import InvestigationDashboard from './pages/InvestigationDashboard';
import type { AnalysisResult } from './types';
import './index.css';

function App() {
  const [currentResult, setCurrentResult] = useState<AnalysisResult | null>(null);

  const handleAnalysisComplete = (result: AnalysisResult) => {
    setCurrentResult(result);

    // Save the latest analysis so it can be exported if needed
    localStorage.setItem(
      'phishscope_recent_analysis',
      JSON.stringify(result)
    );
  };

  const handleNewAnalysis = () => {
    // Clear the previous analysis
    localStorage.removeItem('phishscope_recent_analysis');
    setCurrentResult(null);
  };

  return (
    <div className="app-container">
      {currentResult ? (
        <InvestigationDashboard
          result={currentResult}
          onNewAnalysis={handleNewAnalysis}
        />
      ) : (
        <LandingPage
          onAnalysisComplete={handleAnalysisComplete}
        />
      )}
    </div>
  );
}

export default App;
