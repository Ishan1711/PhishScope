import os
from groq import Groq
from config import ActiveConfig
from app.models.analysis import AnalysisResult

class AIExplainer:
    """Service to generate a simple English explanation of the phishing analysis using LLM."""
    
    @staticmethod
    def generate_explanation(analysis: AnalysisResult) -> str:
        """Calls the LLM API to generate an explanation."""
        
        if not ActiveConfig.GROQ_API_KEY:
            return "AI Explanation is unavailable because the Groq API key is not configured."
            
        try:
            client = Groq(
                api_key=ActiveConfig.GROQ_API_KEY,
                timeout=15.0,
                max_retries=2
            )
            
            prompt = AIExplainer._build_prompt(analysis)
            
            # Using streaming response conceptually or just standard call with timeout
            response = client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model=ActiveConfig.MODEL_NAME,
                temperature=0.3,
                max_tokens=300
            )
            
            return response.choices[0].message.content.strip()
        except Exception as e:
            # If the API fails, return a safe fallback message
            return f"Error generating AI explanation. Please rely on the indicators above. (Details: {str(e)})"

    @staticmethod
    def _build_prompt(analysis: AnalysisResult) -> str:
        header = analysis.header_data
        risk = analysis.risk_assessment
        
        indicators_text = "\n".join([f"- {ind.name}: {ind.description}" for ind in risk.indicators])
        if not indicators_text:
            indicators_text = "None."
            
        prompt = f"""
You are an expert cybersecurity analyst. Explain the following email header analysis to a non-technical user in simple English (maximum 3-4 sentences).

Email Subject: {header.subject}
From: {header.from_address}
Threat Level: {risk.threat_level}
Threat Score: {risk.threat_score}/100

Identified Indicators:
{indicators_text}

Instructions:
1. State clearly if the email is safe, suspicious, or highly suspicious.
2. Explain *why* in simple terms based ONLY on the indicators provided.
3. Do not use overly technical jargon (e.g., explain what SPF/DKIM failure means in plain English, like "the sender's identity couldn't be verified").
4. Be professional and objective.
"""
        return prompt
