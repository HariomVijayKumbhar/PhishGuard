import OpenAI from 'openai';
import { SYSTEM_PROMPT, buildUserAnalysisPrompt } from '../promptTemplates.js';

export async function callGroq(parsedEmail, groundingPatterns = []) {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey || apiKey.includes('your_groq_api_key')) {
    throw new Error('GROQ_API_KEY is not configured in backend environment');
  }

  const client = new OpenAI({
    apiKey,
    baseURL: 'https://api.groq.com/openai/v1'
  });

  let model = process.env.GROQ_MODEL || 'openai/gpt-oss-20b';
  if (!model || model.trim() === 'auto' || model.toLowerCase().includes('auto')) {
    model = 'openai/gpt-oss-20b';
  }
  const userPrompt = buildUserAnalysisPrompt(parsedEmail, groundingPatterns);

  const response = await client.chat.completions.create({
    model,
    temperature: 0.1,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: userPrompt }
    ]
  });

  const rawText = response.choices?.[0]?.message?.content || '';
  return {
    rawOutput: rawText,
    provider: 'groq',
    model
  };
}
