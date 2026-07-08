import React, { useState } from 'react';
import Header from '../components/common/Header';
import Card from '../components/common/Card';
import Button from '../components/common/Button';
import FileUploader from '../components/input/FileUploader';
import HeaderInputArea from '../components/input/HeaderInputArea';
import { analyzeText, analyzeFile } from '../services/api';
import type { AnalysisResult } from '../types';
import './LandingPage.css';

interface LandingPageProps {
  onAnalysisComplete: (result: AnalysisResult) => void;
}

const LandingPage: React.FC<LandingPageProps> = ({ onAnalysisComplete }) => {
  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    setIsLoading(true);
    setError(null);
    try {
      let result: AnalysisResult;
      if (activeTab === 'upload' && selectedFile) {
        result = await analyzeFile(selectedFile);
      } else if (activeTab === 'paste' && rawText.trim()) {
        result = await analyzeText(rawText);
      } else {
        throw new Error("Please provide an email header to analyze.");
      }
      onAnalysisComplete(result);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.error || err.message || "An unknown error occurred during analysis.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="landing-layout">
      <Header />
      
      <main className="landing-main">
        <div className="hero-section">
          <h1 className="hero-title">Email Header Analysis</h1>
          <p className="hero-subtitle">
            Detect phishing, spoofing, and authentication failures instantly using advanced heuristics and AI.
          </p>
        </div>

        <Card className="analysis-card">
          <div className="tabs">
            <button 
              className={`tab-btn ${activeTab === 'upload' ? 'active' : ''}`}
              onClick={() => setActiveTab('upload')}
            >
              File Upload
            </button>
            <button 
              className={`tab-btn ${activeTab === 'paste' ? 'active' : ''}`}
              onClick={() => setActiveTab('paste')}
            >
              Paste Headers
            </button>
          </div>

          <div className="tab-content">
            {activeTab === 'upload' ? (
              <FileUploader onFileSelect={setSelectedFile} />
            ) : (
              <HeaderInputArea value={rawText} onChange={setRawText} />
            )}
          </div>

          {error && <div className="error-message">{error}</div>}

          <div className="action-row">
            <Button 
              onClick={handleAnalyze} 
              isLoading={isLoading}
              disabled={(activeTab === 'upload' && !selectedFile) || (activeTab === 'paste' && !rawText.trim())}
            >
              Analyze Header
            </Button>
          </div>
        </Card>
      </main>
    </div>
  );
};

export default LandingPage;
