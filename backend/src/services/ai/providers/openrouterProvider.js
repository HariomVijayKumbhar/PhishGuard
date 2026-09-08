import OpenAI from 'openai';
import { SYSTEM_PROMPT, buildUserAnalysisPrompt } from '../promptTemplates.js';

export async function callOpenRouter(parsedEmail, groundingPatterns = []) {
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey || apiKey.includes('your_openrouter_api_key')) {
    throw new Error('OPENROUTER_API_KEY is not configured in backend environment');
  }

  const defaultHeaders = {};
  if (process.env.OPENROUTER_SITE_URL) {
    defaultHeaders['HTTP-Referer'] = process.env.OPENROUTER_SITE_URL;
  }
  if (process.env.OPENROUTER_SITE_NAME) {
    defaultHeaders['X-Title'] = process.env.OPENROUTER_SITE_NAME;
  }

  const client = new OpenAI({
    apiKey,
    baseURL: 'https://openrouter.ai/api/v1',
    defaultHeaders: Object.keys(defaultHeaders).length > 0 ? defaultHeaders : undefined
  });

  const model = process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.3-70b-instruct';
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
    provider: 'openrouter',
    model
  };
}
