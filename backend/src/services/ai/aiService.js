import { callAnthropicClaude } from './providers/anthropicProvider.js';
import { callOpenAI } from './providers/openaiProvider.js';
import { callGoogleGemini } from './providers/geminiProvider.js';
import { callGroq } from './providers/groqProvider.js';
import { callOpenRouter } from './providers/openrouterProvider.js';
import { callMockAI } from './providers/mockProvider.js';
import { retrieveRelevantGroundingPatterns } from './ragGrounding.js';

export class AIClassificationError extends Error {
  constructor(message, code = 'AI_CLASSIFICATION_FAILED', statusCode = 502) {
    super(message);
    this.name = 'AIClassificationError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Strip Markdown code fences and whitespace from LLM text responses
 */
export function cleanJsonOutput(rawText) {
  if (!rawText || typeof rawText !== 'string') return '';

  let cleaned = rawText.trim();
  // Remove markdown code fence ```json ... ``` or ``` ... ```
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '');
  cleaned = cleaned.replace(/\s*```$/i, '');
  return cleaned.trim();
}

/**
 * Validate that parsed JSON adheres strictly to the required PhishGuard schema
 */
export function validateSchema(data) {
  if (!data || typeof data !== 'object') {
    throw new Error('AI output is not a valid JSON object');
  }

  const { risk_score, verdict, tactics_detected, explanation, safe_summary } = data;

  // Validate risk_score (0-100 number)
  const numScore = Number(risk_score);
  if (isNaN(numScore) || numScore < 0 || numScore > 100) {
    throw new Error(`Invalid risk_score: ${risk_score}. Must be integer between 0 and 100.`);
  }

  // Validate verdict ('safe' | 'suspicious' | 'phishing')
  const validVerdicts = ['safe', 'suspicious', 'phishing'];
  if (!validVerdicts.includes(verdict)) {
    throw new Error(`Invalid verdict: "${verdict}". Must be one of: safe, suspicious, phishing.`);
  }

  // Validate tactics_detected (array)
  if (!Array.isArray(tactics_detected)) {
    throw new Error('tactics_detected must be an array of strings');
  }

  // Validate explanation & safe_summary (strings)
  if (typeof explanation !== 'string' || explanation.trim().length === 0) {
    throw new Error('explanation must be a non-empty string');
  }
  if (typeof safe_summary !== 'string' || safe_summary.trim().length === 0) {
    throw new Error('safe_summary must be a non-empty string');
  }

  return {
    risk_score: Math.round(numScore),
    verdict,
    tactics_detected: tactics_detected.map(t => String(t).trim()),
    explanation: explanation.trim(),
    safe_summary: safe_summary.trim()
  };
}

/**
 * Primary AI classification entrypoint with single retry on parse failure and multi-provider selection
 */
export async function classifyEmailWithAI(parsedEmail, options = {}) {
  const preferredProvider = (options.provider || process.env.DEFAULT_AI_PROVIDER || 'auto').toLowerCase();

  // Retrieve RAG threat intelligence grounding patterns
  const groundingPatterns = retrieveRelevantGroundingPatterns(parsedEmail);

  // Determine provider execution function
  const executeCall = async (providerName) => {
    switch (providerName) {
      case 'anthropic':
      case 'claude':
        return await callAnthropicClaude(parsedEmail, groundingPatterns);
      case 'openai':
      case 'gpt':
        return await callOpenAI(parsedEmail, groundingPatterns);
      case 'gemini':
      case 'google':
        return await callGoogleGemini(parsedEmail, groundingPatterns);
      case 'groq':
        return await callGroq(parsedEmail, groundingPatterns);
      case 'openrouter':
        return await callOpenRouter(parsedEmail, groundingPatterns);
      case 'mock':
        return await callMockAI(parsedEmail, groundingPatterns);
      default:
        throw new Error(`Unknown AI provider: ${providerName}`);
    }
  };

  // Determine list of providers to try
  const getActiveConfiguredProviders = () => {
    const list = [];
    if (process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY.includes('your_openrouter_api_key')) {
      list.push('openrouter');
    }
    if (process.env.GROQ_API_KEY && !process.env.GROQ_API_KEY.includes('your_groq_api_key')) {
      list.push('groq');
    }
    if (process.env.GEMINI_API_KEY && !process.env.GEMINI_API_KEY.includes('your_gemini_api_key')) {
      list.push('gemini');
    }
    if (process.env.OPENAI_API_KEY && !process.env.OPENAI_API_KEY.includes('your_openai_api_key')) {
      list.push('openai');
    }
    if (process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_API_KEY.includes('your_anthropic_api_key')) {
      list.push('anthropic');
    }
    return list;
  };

  let providersToTry = [];
  if (preferredProvider === 'auto') {
    providersToTry = getActiveConfiguredProviders();
    if (providersToTry.length === 0) {
      if (process.env.NODE_ENV === 'test' || options.allowMock) {
        providersToTry = ['mock'];
      } else {
        throw new AIClassificationError(
          'No AI provider API key configured (ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY, GROQ_API_KEY, or OPENROUTER_API_KEY required).',
          'AI_PROVIDER_NOT_CONFIGURED',
          503
        );
      }
    }
  } else {
    providersToTry = [preferredProvider];
  }

  let lastError = null;

  for (const provider of providersToTry) {
    const maxAttempts = 2;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const { rawOutput, model } = await executeCall(provider);
        const cleaned = cleanJsonOutput(rawOutput);

        let parsedJson;
        try {
          parsedJson = JSON.parse(cleaned);
        } catch (jsonErr) {
          throw new Error(`Failed to parse AI response as JSON: ${jsonErr.message}`);
        }

        const validated = validateSchema(parsedJson);

        return {
          ...validated,
          ai_metadata: {
            provider,
            model,
            attempt,
            grounding_patterns_used: groundingPatterns.map(p => p.id)
          }
        };
      } catch (err) {
        lastError = err;
        console.warn(`[AI Classifier] Provider "${provider}" attempt ${attempt} failed:`, err.message);

        // If explicitly requested single provider has missing credentials, abort immediately
        if (preferredProvider !== 'auto' && err.message.includes('not configured')) {
          throw new AIClassificationError(err.message, 'AI_PROVIDER_NOT_CONFIGURED', 503);
        }
      }
    }
  }

  // Hard-fail if all providers exhausted
  throw new AIClassificationError(
    `AI classification failed after trying provider(s) [${providersToTry.join(', ')}]: ${lastError?.message || 'Unknown error'}`,
    'AI_SCHEMA_VALIDATION_FAILED',
    502
  );
}
