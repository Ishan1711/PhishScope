import os
from groq import Groq
from config import ActiveConfig
from app.models.analysis import AnalysisResult


class AIExplainer:
    """Service to generate a structured SOC-analyst-style explanation using Groq LLM."""

    @staticmethod
    def generate_explanation(analysis: AnalysisResult) -> str:
        """Calls the LLM API to generate a structured analysis explanation."""

        if not ActiveConfig.GROQ_API_KEY:
            return "AI Explanation is unavailable because the Groq API key is not configured."

        try:
            client = Groq(
                api_key=ActiveConfig.GROQ_API_KEY,
                timeout=30.0,
                max_retries=2
            )

            system_prompt = (
                "You are a Senior SOC (Security Operations Center) Analyst with 15 years of experience in "
                "email threat intelligence, phishing investigation, and incident response. "
                "You produce concise, professional, structured security reports. "
                "Your output must use the EXACT section headers specified and nothing else. "
                "Never hallucinate indicators not present in the data. "
                "Use definitive, confident language. Avoid hedging phrases like 'may potentially' or 'could possibly'."
            )

            prompt = AIExplainer._build_prompt(analysis)

            response = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                model=ActiveConfig.MODEL_NAME,
                temperature=0.2,
                max_tokens=700,
            )

            return response.choices[0].message.content.strip()
        except Exception as e:
            return (
                f"AI analysis unavailable. Please rely on the indicators above.\n"
                f"Error: {str(e)}"
            )

    @staticmethod
    def _build_prompt(analysis: AnalysisResult) -> str:
        header = analysis.header_data
        risk = analysis.risk_assessment

        # Format indicators
        indicators_text = "\n".join([
            f"  [{ind.severity}] {ind.name} (+{ind.score_contribution}pts): {ind.description}"
            for ind in risk.indicators
        ]) or "  None detected."

        # Format score breakdown
        breakdown_text = "\n".join([
            f"  +{item.points}pts — {item.reason} [{item.category}]"
            for item in risk.score_breakdown
        ]) or "  No score contributors."

        # Format URL threats
        url_threats = [u for u in risk.url_indicators if u.risk_level in ("SUSPICIOUS", "HIGH")]
        url_text = "\n".join([
            f"  [{u.risk_level}] {u.url[:80]} — {', '.join(u.reasons[:2])}"
            for u in url_threats[:5]
        ]) or "  No URL threats detected."

        # Format MITRE techniques
        mitre_text = "\n".join([
            f"  {t.technique_id} ({t.tactic}): {t.technique_name}"
            for t in risk.mitre_techniques
        ]) or "  No MITRE techniques mapped."

        prompt = f"""
Analyze this email header investigation and produce a structured report using EXACTLY the following format and section headers. Keep each section concise (2-4 sentences max per section).

=== EMAIL DATA ===
Subject: {header.subject}
From: {header.from_address}
Display Name: {header.display_name or 'N/A'}
Sender Domain: {header.from_domain or 'Unknown'}
Threat Score: {risk.threat_score}/100
Threat Level: {risk.threat_level}
Confidence: {risk.confidence_score}%
SPF: {header.auth_results.spf} | DKIM: {header.auth_results.dkim} | DMARC: {header.auth_results.dmarc}

=== IOC SUMMARY ===
Total Indicators: {risk.ioc_summary.total}
HIGH: {risk.ioc_summary.high_count} | MEDIUM: {risk.ioc_summary.medium_count} | LOW: {risk.ioc_summary.low_count}
Spoofing Detected: {risk.ioc_summary.spoofing_detected}
Suspicious Domain: {risk.ioc_summary.domain_suspicious}

=== INDICATORS ===
{indicators_text}

=== SCORE BREAKDOWN ===
{breakdown_text}

=== URL THREATS ===
{url_text}

=== MITRE ATT&CK ===
{mitre_text}

=== REQUIRED OUTPUT FORMAT ===
Produce a report with EXACTLY these 6 section headers:

## EXECUTIVE SUMMARY
[2-3 sentences: state the verdict clearly, threat score, and primary reason. No jargon.]

## TECHNICAL ANALYSIS
[2-4 sentences: explain the authentication results (SPF/DKIM/DMARC), header anomalies, and what the score breakdown reveals. Use technical but clear language.]

## THREAT EXPLANATION
[2-3 sentences: explain what type of attack this is (e.g., phishing, spoofing, BEC), how it works, and why it is dangerous.]

## RECOMMENDED ACTIONS
[3-5 bullet points for a security team: what to do right now.]

## SOC ANALYST NOTES
[2-3 sentences: additional observations for a senior analyst, including any MITRE ATT&CK context.]

## END USER RECOMMENDATION
[1-2 sentences in plain, non-technical language telling the email recipient what to do.]
"""
        return prompt
