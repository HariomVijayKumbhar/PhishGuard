import Anthropic from '@anthropic-ai/sdk';
import { SYSTEM_PROMPT, buildUserAnalysisPrompt } from '../promptTemplates.js';

export async function callAnthropicClaude(parsedEmail, groundingPatterns = []) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || apiKey.includes('your_anthropic_api_key')) {
    throw new Error('ANTHROPIC_API_KEY is not configured in backend environment');
  }

  const client = new Anthropic({ apiKey });
  const model = process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20241022';
  const userPrompt = buildUserAnalysisPrompt(parsedEmail, groundingPatterns);

  const response = await client.messages.create({
    model,
    max_tokens: 1024,
    system: SYSTEM_PROMPT,
    messages: [
      {
        role: 'user',
        content: userPrompt
      }
    ]
  });

  const rawText = response.content?.[0]?.text || '';
  return {
    rawOutput: rawText,
    provider: 'anthropic',
    model
  };
}
