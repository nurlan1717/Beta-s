import os
import sys

try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False
    print("[-] 'google-generativeai' not found. Install: pip install google-generativeai")

def generate_phishing_email(api_key, company_type, target_role, urgency="High"):
    """
    Generates a phishing email content using Gemini AI.
    """
    if not HAS_GENAI:
        return "Error: AI Library not installed."

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')

        prompt = f"""
        You are a Red Team Adversary Simulation Generator.
        Write a convincing, simulated phishing email targeting an employee at a {company_type} company.
        The target's role is {target_role}.
        The scenario urgency is {urgency}.
        
        The goal is to get them to download an attachment or click a link to 'loader.py' (The Security Update).
        
        Format the output exactly like this:
        SUBJECT: [Subject Line]
        BODY: [Email Body]
        
        Keep it professional but urgent. Do not include placeholders like [Your Name], use fake generated names.
        """

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        return f"Error generating content: {e}"

def main():
    print("=== AI PHISHING GENERATOR (Gemini Powered) ===")
    print("This module generates a context-aware phishing email to test your users.")
    
    api_key = input("Enter your Google Gemini API Key: ").strip()
    if not api_key:
        print("[-] API Key is required.")
        return

    print("\n--- Campaign Configuration ---")
    company = input("Target Industry (e.g., Healthcare, Finance, Travel): ").strip()
    role = input("Target Role (e.g., HR Manager, IT Admin): ").strip()
    urgency = input("Urgency Level (Low, Medium, High): ").strip()

    print("\n[*] Generating Campaign Material...")
    email_content = generate_phishing_email(api_key, company, role, urgency)
    
    print("\n" + "="*40)
    print("GENERATED PHISHING EMAIL")
    print("="*40)
    print(email_content)
    print("="*40)
    
    print("\n[+] Next Step: Copy this content to your email sender.")
    print("[+] Ensure the link points to: 'loader.py' (renamed as 'Security_Patch.exe' or similar).")

if __name__ == "__main__":
    main()
