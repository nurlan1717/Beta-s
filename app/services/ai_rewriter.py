"""
Phishing Awareness Simulator - AI Template Rewriter
====================================================
Uses Gemini AI to rewrite phishing templates for clarity and professionalism.

SAFETY REQUIREMENTS (STRICTLY ENFORCED):
- Must NOT add urgency, threats, or authority pressure
- Must NOT request passwords, MFA codes, or credentials
- Must KEEP the [SIMULATION] banner
- Must ONLY improve clarity and professionalism
- Must NOT make the email more deceptive
"""

import os
from typing import Optional, Dict

# Gemini API configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
AI_REWRITE_ENABLED = os.getenv("AI_REWRITE_ENABLED", "true").lower() == "true"

# Try to import Google Generative AI
try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False


# Safety prompt - enforces training-only content
SAFETY_PROMPT = """You are a security awareness training content editor.

Your task is to SLIGHTLY improve the clarity and professionalism of a phishing simulation email template.

STRICT RULES YOU MUST FOLLOW:
1. KEEP the [SIMULATION] banner - it must remain visible
2. DO NOT add urgency language like "immediately", "urgent", "act now"
3. DO NOT add threatening language like "your account will be suspended"
4. DO NOT add authority pressure like "CEO demands" or "legal action"
5. DO NOT request passwords, MFA codes, PINs, or any credentials
6. DO NOT make the email more deceptive or convincing
7. ONLY improve grammar, spelling, and professional tone
8. KEEP the same general structure and length
9. KEEP all placeholder variables like {recipient_name}, {tracking_link}

This is for TRAINING purposes only. The goal is NOT to trick users, but to help them recognize phishing patterns.

Return ONLY the improved email content, nothing else."""


def rewrite_template_with_ai(
    subject: str,
    body_text: str,
    target_industry: str = None,
    target_role: str = None
) -> Optional[Dict[str, str]]:
    """
    Rewrite a phishing template using Gemini AI.
    
    Returns dict with 'subject' and 'body_text' or None if failed.
    
    SAFETY: This function enforces strict rules to prevent
    generating harmful or deceptive content.
    """
    if not AI_REWRITE_ENABLED:
        return None
    
    if not HAS_GENAI:
        print("[-] google-generativeai not installed. Run: pip install google-generativeai")
        return None
    
    if not GEMINI_API_KEY:
        print("[-] GEMINI_API_KEY not configured")
        return None
    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
        
        # Build the prompt
        context = ""
        if target_industry:
            context += f"Target industry context: {target_industry}\n"
        if target_role:
            context += f"Target role context: {target_role}\n"
        
        prompt = f"""{SAFETY_PROMPT}

{context}

ORIGINAL SUBJECT:
{subject}

ORIGINAL BODY:
{body_text}

Provide the improved version in this exact format:
SUBJECT: [improved subject line]
BODY: [improved body text]
"""
        
        response = model.generate_content(prompt)
        result_text = response.text.strip()
        
        # Parse the response
        if "SUBJECT:" in result_text and "BODY:" in result_text:
            parts = result_text.split("BODY:", 1)
            subject_part = parts[0].replace("SUBJECT:", "").strip()
            body_part = parts[1].strip() if len(parts) > 1 else body_text
            
            # Safety check - ensure [SIMULATION] is still present
            if "[SIMULATION]" not in subject_part and "[SIMULATION]" not in body_part:
                # Add it back if AI removed it
                subject_part = "[SIMULATION] " + subject_part.replace("[SIMULATION]", "").strip()
            
            return {
                "subject": subject_part,
                "body_text": body_part
            }
        else:
            # Couldn't parse, return original
            return None
            
    except Exception as e:
        print(f"[-] AI rewrite failed: {e}")
        return None


def generate_custom_template(
    scenario_type: str,
    target_industry: str = "General",
    target_role: str = "Employee"
) -> Optional[Dict[str, str]]:
    """
    Generate a custom phishing template using AI.
    
    SAFETY: Generated content is strictly controlled to be
    training-appropriate only.
    """
    if not AI_REWRITE_ENABLED or not HAS_GENAI or not GEMINI_API_KEY:
        return None
    
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"""{SAFETY_PROMPT}

Create a NEW phishing awareness training email template.

Scenario type: {scenario_type}
Target industry: {target_industry}
Target role: {target_role}

The email MUST:
1. Start with "[SIMULATION] This is a phishing awareness training message."
2. Be clearly a training exercise
3. Include placeholder {{recipient_name}} for the recipient's name
4. Include placeholder {{tracking_link}} for the tracking link
5. Be professional but NOT deceptive
6. NOT request any credentials or sensitive information

Provide the template in this exact format:
SUBJECT: [subject line with [SIMULATION] prefix]
BODY: [email body text]
"""
        
        response = model.generate_content(prompt)
        result_text = response.text.strip()
        
        if "SUBJECT:" in result_text and "BODY:" in result_text:
            parts = result_text.split("BODY:", 1)
            subject_part = parts[0].replace("SUBJECT:", "").strip()
            body_part = parts[1].strip() if len(parts) > 1 else ""
            
            # Ensure [SIMULATION] is present
            if "[SIMULATION]" not in subject_part:
                subject_part = "[SIMULATION] " + subject_part
            
            if "[SIMULATION]" not in body_part:
                body_part = "[SIMULATION] This is a phishing awareness training message.\n\n" + body_part
            
            return {
                "subject": subject_part,
                "body_text": body_part
            }
        
        return None
        
    except Exception as e:
        print(f"[-] AI template generation failed: {e}")
        return None


def check_ai_available() -> Dict[str, bool]:
    """Check if AI features are available."""
    return {
        "enabled": AI_REWRITE_ENABLED,
        "library_installed": HAS_GENAI,
        "api_key_configured": bool(GEMINI_API_KEY),
        "available": AI_REWRITE_ENABLED and HAS_GENAI and bool(GEMINI_API_KEY)
    }
