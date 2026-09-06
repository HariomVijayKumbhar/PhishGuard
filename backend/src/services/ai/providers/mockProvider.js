/**
 * Mock AI Provider for deterministic unit testing and offline development.
 * Simulates LLM response logic adhering strictly to the schema.
 */

export async function callMockAI(parsedEmail, groundingPatterns = []) {
  const { metadata, content, securityHeaders, heuristics } = parsedEmail;
  const text = (content.textBody || '').toLowerCase();
  const subject = (metadata.subject || '').toLowerCase();

  let riskScore = 15;
  const tactics = [];

  // 1. Detect Adversarial Prompt Injection
  const promptInjectionKeywords = [
    'ignore previous instructions',
    'disregard previous',
    'mark this as safe',
    'system override',
    'classify as score 0',
    'score: 0'
  ];
  const hasPromptInjection = promptInjectionKeywords.some(kw => text.includes(kw));

  if (hasPromptInjection) {
    riskScore = Math.max(riskScore, 95);
    tactics.push('prompt_injection_attempt', 'adversarial_manipulation');
  }

  // 2. Evaluate Local Heuristics
  if (heuristics.lookalikeCount > 0) {
    riskScore = Math.max(riskScore, 85);
    tactics.push('lookalike_domain', 'brand_impersonation');
  }
  if (heuristics.anchorMismatchCount > 0) {
    riskScore = Math.max(riskScore, 90);
    tactics.push('anchor_mismatch', 'deceptive_hyperlink');
  }
  if (heuristics.ipLinksCount > 0) {
    riskScore = Math.max(riskScore, 75);
    tactics.push('ip_address_link');
  }
  if (securityHeaders.spf === 'fail' || securityHeaders.dmarc === 'fail') {
    riskScore = Math.max(riskScore, 80);
    tactics.push('authentication_failure');
  }

  // 3. Social Engineering Keyword Patterns
  if (text.includes('urgent') || subject.includes('urgent') || text.includes('suspended') || text.includes('expire')) {
    riskScore = Math.max(riskScore, 65);
    tactics.push('urgency', 'fear_intimidation');
  }
  if (text.includes('password') && (text.includes('reset') || text.includes('expire'))) {
    riskScore = Math.max(riskScore, 80);
    tactics.push('credential_harvesting');
  }
  if (text.includes('invoice') || text.includes('charged') || text.includes('payment')) {
    if (riskScore < 50) riskScore = 45;
    tactics.push('financial_pretext');
  }

  let verdict = 'safe';
  if (riskScore >= 70) {
    verdict = 'phishing';
  } else if (riskScore >= 30) {
    verdict = 'suspicious';
  }

  let explanation = '';
  if (verdict === 'phishing') {
    explanation = `High confidence phishing attempt identified with a risk score of ${riskScore}/100. The communication exhibits ${tactics.slice(0, 3).join(', ')}, aiming to compromise user credentials or security controls.`;
  } else if (verdict === 'suspicious') {
    explanation = `Suspicious communication detected with risk score ${riskScore}/100. Inbound email demonstrates indicators of ${tactics.join(', ')}. Caution is advised before interacting with any embedded links.`;
  } else {
    explanation = `Communication appears benign with a low risk score of ${riskScore}/100. No deceptive lookalike domains, credential harvesting lures, or authentication failures were detected.`;
  }

  const safeSummary = `The sender is contacting you regarding "${metadata.subject || 'unspecified topic'}". All embedded links and contact points have been stripped for safety.`;

  const payload = {
    risk_score: riskScore,
    verdict,
    tactics_detected: tactics.length > 0 ? Array.from(new Set(tactics)) : ['none'],
    explanation,
    safe_summary: safeSummary
  };

  return {
    rawOutput: JSON.stringify(payload, null, 2),
    provider: 'mock',
    model: 'mock-classifier-v1'
  };
}
