import axios from 'axios';
import type { AnalysisResult } from '../types';

const API_BASE = 'http://localhost:5000/api/v1';

export const analyzeText = async (text: string): Promise<AnalysisResult> => {
  const response = await axios.post(`${API_BASE}/analyze/text`, { text });
  return response.data;
};

export const analyzeFile = async (file: File): Promise<AnalysisResult> => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await axios.post(`${API_BASE}/analyze/file`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  });
  return response.data;
};

export const exportPdf = async (analysis: AnalysisResult): Promise<void> => {
  const response = await axios.post(`${API_BASE}/export/pdf`, analysis, {
    responseType: 'blob'
  });
  
  // Trigger download
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `${analysis.investigation_id}_Report.pdf`);
  document.body.appendChild(link);
  link.click();
  link.remove();
};

export const exportJson = async (analysis: AnalysisResult): Promise<void> => {
  const response = await axios.post(`${API_BASE}/export/json`, analysis, {
    responseType: 'blob'
  });
  
  // Trigger download
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `${analysis.investigation_id}_Report.json`);
  document.body.appendChild(link);
  link.click();
  link.remove();
};
