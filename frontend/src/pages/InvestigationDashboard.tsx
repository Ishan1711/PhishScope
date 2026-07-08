import React from 'react';
import Header from '../components/common/Header';
import Card from '../components/common/Card';
import Button from '../components/common/Button';
import ScoreWidget from '../components/investigation/ScoreWidget';
import AuthStatusGrid from '../components/investigation/AuthStatusGrid';
import IndicatorList from '../components/investigation/IndicatorList';
import FieldViewer from '../components/investigation/FieldViewer';
import Timeline from '../components/investigation/Timeline';
import AIExplanationCard from '../components/investigation/AIExplanationCard';
import ScoreBreakdown from '../components/investigation/ScoreBreakdown';
import IocSummaryWidget from '../components/investigation/IocSummaryWidget';
import UrlAnalysis from '../components/investigation/UrlAnalysis';
import MitreCard from '../components/investigation/MitreCard';
import type { AnalysisResult } from '../types';
import { exportPdf, exportJson } from '../services/api';
import { Download, FileJson, ArrowLeft } from 'lucide-react';
import './InvestigationDashboard.css';

interface InvestigationDashboardProps {
  result: AnalysisResult;
  onNewAnalysis: () => void;
}

const InvestigationDashboard: React.FC<InvestigationDashboardProps> = ({ result, onNewAnalysis }) => {
  const handleExportPDF = async () => {
    try {
      await exportPdf(result);
    } catch {
      alert("Failed to export PDF.");
    }
  };

  const handleExportJSON = async () => {
    try {
      await exportJson(result);
    } catch {
      alert("Failed to export JSON.");
    }
  };

  const basicFields = [
    { label: 'Subject', value: result.header_data.subject },
    { label: 'From', value: result.header_data.from_address },
    { label: 'To', value: result.header_data.to_address },
    { label: 'Date', value: result.header_data.date },
    { label: 'Message-ID', value: result.header_data.message_id },
    { label: 'Originating IP', value: result.header_data.originating_ip },
  ];

  return (
    <div className="dashboard-layout">
      <Header />
      
      <main className="dashboard-main">
        <div className="dashboard-header">
          <div className="dashboard-title-area">
            <button className="back-btn" onClick={onNewAnalysis} title="New Analysis">
              <ArrowLeft size={20} />
            </button>
            <div>
              <h1 className="dashboard-title">Investigation Dashboard</h1>
              <div className="dashboard-meta">
                <span>ID: {result.investigation_id}</span>
                <span className="meta-separator">•</span>
                <span>Analyzed: {new Date(result.analysis_time).toLocaleString()}</span>
              </div>
            </div>
          </div>
          <div className="dashboard-actions">
            <Button variant="secondary" onClick={handleExportJSON}>
              <FileJson size={16} /> JSON
            </Button>
            <Button variant="primary" onClick={handleExportPDF}>
              <Download size={16} /> PDF Report
            </Button>
          </div>
        </div>

        <AIExplanationCard explanation={result.ai_explanation} />

        <div className="dashboard-grid">
          {/* Left Column */}
          <div className="grid-column left-col">
            <Card title="Threat Assessment" className="mb-4">
              <ScoreWidget risk={result.risk_assessment} />
            </Card>

            {result.risk_assessment.score_breakdown && result.risk_assessment.score_breakdown.length > 0 && (
              <Card title="Risk Breakdown" className="mb-4">
                <ScoreBreakdown 
                  breakdown={result.risk_assessment.score_breakdown} 
                  totalScore={result.risk_assessment.threat_score} 
                />
              </Card>
            )}

            {result.risk_assessment.ioc_summary && (
              <Card title="IOC Summary" className="mb-4">
                <IocSummaryWidget ioc={result.risk_assessment.ioc_summary} />
              </Card>
            )}

            <Card title="Phishing Indicators" className="mb-4">
              <IndicatorList indicators={result.risk_assessment.indicators} />
            </Card>

            <Card title="Authentication Results" className="mb-4">
              <AuthStatusGrid auth={result.header_data.auth_results} />
              {result.header_data.auth_results.raw_details && (
                <div className="raw-auth-details mt-4">
                  <span className="raw-label">Raw Header:</span>
                  <div className="raw-content">
                    {result.header_data.auth_results.raw_details}
                  </div>
                </div>
              )}
            </Card>
          </div>

          {/* Right Column */}
          <div className="grid-column right-col">
            <Card title="Extracted Details" className="mb-4">
              <FieldViewer fields={basicFields} />
            </Card>

            <Card title="Routing Timeline" className="mb-4">
              <Timeline hops={result.header_data.hops} />
            </Card>

            {result.risk_assessment.url_indicators && result.risk_assessment.url_indicators.length > 0 && (
              <Card title="URL Analysis" className="mb-4">
                <UrlAnalysis urlIndicators={result.risk_assessment.url_indicators} />
              </Card>
            )}

            {result.risk_assessment.mitre_techniques && result.risk_assessment.mitre_techniques.length > 0 && (
              <Card title="MITRE ATT&CK® Mapping" className="mb-4">
                <MitreCard techniques={result.risk_assessment.mitre_techniques} />
              </Card>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default InvestigationDashboard;
