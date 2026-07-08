export interface Hop {
  hop_number: number;
  from_server: string;
  by_server: string;
  with_protocol: string;
  timestamp: string;
  delay: string;
}

export interface AuthenticationResults {
  spf: string;
  dkim: string;
  dmarc: string;
  raw_details: string;
}

export interface EmailHeader {
  subject: string;
  from_address: string;
  to_address: string;
  date: string;
  reply_to: string;
  return_path: string;
  message_id: string;
  mime_version: string;
  content_type: string;
  user_agent: string;
  originating_ip: string;
  hops: Hop[];
  auth_results: AuthenticationResults;
  raw_headers: Record<string, any>;
}

export interface Indicator {
  name: string;
  description: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface RiskScore {
  threat_score: number;
  threat_level: 'SAFE' | 'SUSPICIOUS' | 'HIGHLY SUSPICIOUS';
  confidence_score: number;
  indicators: Indicator[];
}

export interface AnalysisResult {
  investigation_id: string;
  analysis_time: string;
  header_data: EmailHeader;
  risk_assessment: RiskScore;
  ai_explanation?: string;
}
