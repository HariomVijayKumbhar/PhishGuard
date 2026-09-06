import { GoogleGenAI } from '@google/genai';
import { SYSTEM_PROMPT, buildUserAnalysisPrompt } from '../promptTemplates.js';

export async function callGoogleGemini(parsedEmail, groundingPatterns = []) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey.includes('your_gemini_api_key')) {
    throw new Error('GEMINI_API_KEY is not configured in backend environment');
  }

  const ai = new GoogleGenAI({ apiKey });
  const model = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
  const userPrompt = buildUserAnalysisPrompt(parsedEmail, groundingPatterns);

  const response = await ai.models.generateContent({
    model,
    contents: userPrompt,
    config: {
      systemInstruction: SYSTEM_PROMPT,
      responseMimeType: 'application/json'
    }
  });

  const rawText = response.text || '';
  return {
    rawOutput: rawText,
    provider: 'gemini',
    model
  };
}
