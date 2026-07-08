export interface Hop {
  hop_number: number;
  from_server: string;
  by_server: string;
  with_protocol: string;
  timestamp: string;
  delay: string;
  ip_address: string;
  is_suspicious: boolean;
}

export interface AuthenticationResults {
  spf: string;
  dkim: string;
  dmarc: string;
  raw_details: string;
  spf_domain: string;
  dkim_domain: string;
  dkim_selector: string;
  dmarc_policy: string;
}

export interface EmailHeader {
  subject: string;
  from_address: string;
  display_name: string;
  from_domain: string;
  to_address: string;
  cc_address: string;
  date: string;
  reply_to: string;
  reply_to_domain: string;
  return_path: string;
  return_path_domain: string;
  message_id: string;
  mime_version: string;
  content_type: string;
  user_agent: string;
  x_mailer: string;
  x_spam_status: string;
  x_spam_score: string;
  originating_ip: string;
  ip_is_hidden: boolean;
  ip_provider: string;
  hops: Hop[];
  auth_results: AuthenticationResults;
  raw_headers: Record<string, any>;
  urls_found: string[];
  header_count: number;
  duplicate_headers: string[];
}

export interface Indicator {
  name: string;
  description: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  score_contribution: number;
  category: string;
}

export interface ScoreItem {
  reason: string;
  points: number;
  category: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface UrlIndicator {
  url: string;
  domain: string;
  protocol: string;
  risk_level: 'SAFE' | 'SUSPICIOUS' | 'HIGH';
  reasons: string[];
  is_shortened: boolean;
  is_ip_based: boolean;
  is_encoded: boolean;
  is_homograph: boolean;
  suspicious_tld: boolean;
}

export interface IocSummary {
  total: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  url_threats: number;
  auth_failures: number;
  spoofing_detected: boolean;
  domain_suspicious: boolean;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  url: string;
}

export interface RiskScore {
  threat_score: number;
  threat_level: 'SAFE' | 'SUSPICIOUS' | 'HIGHLY SUSPICIOUS';
  confidence_score: number;
  indicators: Indicator[];
  score_breakdown: ScoreItem[];
  url_indicators: UrlIndicator[];
  ioc_summary: IocSummary;
  mitre_techniques: MitreTechnique[];
}

export interface AnalysisResult {
  investigation_id: string;
  analysis_time: string;
  version: string;
  header_data: EmailHeader;
  risk_assessment: RiskScore;
  ai_explanation?: string;
  analysis_duration_ms: number;
}
