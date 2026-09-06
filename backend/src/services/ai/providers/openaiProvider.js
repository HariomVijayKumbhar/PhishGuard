import OpenAI from 'openai';
import { SYSTEM_PROMPT, buildUserAnalysisPrompt } from '../promptTemplates.js';

export async function callOpenAI(parsedEmail, groundingPatterns = []) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey || apiKey.includes('your_openai_api_key')) {
    throw new Error('OPENAI_API_KEY is not configured in backend environment');
  }

  const client = new OpenAI({ apiKey });
  const model = process.env.OPENAI_MODEL || 'gpt-4o';
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
    provider: 'openai',
    model
  };
}
