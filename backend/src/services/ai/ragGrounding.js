/**
 * RAG Grounding Reference Library:
 * Curated reference patterns of real-world phishing and social engineering tactics.
 * We perform keyword and semantic similarity scoring to retrieve relevant patterns
 * to ground the AI model's judgment and reasoning.
 */

export const PHISHING_PATTERNS_DB = [
  {
    id: 'credential_harvesting_account_suspension',
    category: 'Credential Harvesting',
    tactic: 'urgency_and_fear',
    description: 'Impersonates a major service (PayPal, Microsoft, Google, Apple) warning of immediate account suspension, billing failure, or security lockout unless the user verifies credentials within a tight timeframe (e.g. 24 hours).',
    indicators: ['suspension', 'suspended', 'lockout', 'billing failure', 'restore access', 'verify account', 'unauthorized login', '24 hours', 'action required'],
    typicalBrands: ['PayPal', 'Microsoft', 'Apple', 'Netflix', 'Amazon'],
    baseRisk: 85
  },
  {
    id: 'it_password_expiration',
    category: 'Internal IT Spoofing',
    tactic: 'authority_impersonation',
    description: 'Fakes an internal IT department notice claiming email or Active Directory password will expire today and directs employee to an external or IP-based portal.',
    indicators: ['password expires', 'office365', 'it helpdesk', 'keep same password', 'portal login', 'reset password', 'active directory', 'system administrator'],
    typicalBrands: ['Microsoft Office 365', 'Google Workspace', 'Okta'],
    baseRisk: 90
  },
  {
    id: 'fake_invoice_or_receipt',
    category: 'Financial Fraud',
    tactic: 'financial_panic',
    description: 'Sends an unexpected high-value invoice (e.g. Geek Squad, Norton, PayPal, Apple Store) with a fraudulent customer support number or payment cancellation link designed to elicit an immediate panic response.',
    indicators: ['invoice', 'receipt', 'order confirmed', 'geek squad', 'norton life lock', 'subscription renewed', 'charged $', 'cancel subscription', 'call customer support'],
    typicalBrands: ['Geek Squad', 'Norton', 'PayPal', 'Apple'],
    baseRisk: 80
  },
  {
    id: 'ceo_wire_transfer_gift_card',
    category: 'Business Email Compromise (BEC)',
    tactic: 'pretexting_and_secrecy',
    description: 'Attacker impersonates a CEO or high-level executive asking an assistant or finance personnel for immediate confidential wire transfers or gift cards for client meetings.',
    indicators: ['are you at your desk', 'available for a quick task', 'need gift cards', 'confidential wire transfer', 'in a meeting right now', 'do not call me'],
    typicalBrands: ['Executive Leadership'],
    baseRisk: 95
  },
  {
    id: 'docusign_shared_document',
    category: 'Document Phishing',
    tactic: 'routine_compliance',
    description: 'Fakes an electronic signature request for non-disclosure agreement, payroll update, or tax document leading to a fake authentication form.',
    indicators: ['docusign', 'adobe sign', 'shared a document with you', 'review document', 'sign agreement', 'payroll update', 'w-2 tax statement'],
    typicalBrands: ['DocuSign', 'Adobe Sign', 'Dropbox'],
    baseRisk: 75
  },
  {
    id: 'shipping_delivery_exception',
    category: 'Package Delivery Fraud',
    tactic: 'curiosity_and_urgency',
    description: 'Claims an inbound package cannot be delivered due to incorrect address or unpaid customs fee, requiring credit card entry to reschedule.',
    indicators: ['delivery exception', 'usps', 'fedex', 'dhl', 'ups', 'reschedule delivery', 'customs fee', 'address correction', 'package held'],
    typicalBrands: ['USPS', 'FedEx', 'DHL', 'UPS'],
    baseRisk: 70
  }
];

/**
 * Retrieve the top relevant reference patterns for an email by evaluating keyword overlap
 * against the parsed subject, body, and heuristic indicators.
 */
export function retrieveRelevantGroundingPatterns(parsedEmail, maxResults = 2) {
  const content = `${parsedEmail?.metadata?.subject || ''} ${parsedEmail?.content?.textBody || ''} ${JSON.stringify(parsedEmail?.heuristics?.flaggedIndicators || [])}`.toLowerCase();

  const scored = PHISHING_PATTERNS_DB.map((pattern) => {
    let score = 0;
    for (const kw of pattern.indicators) {
      if (content.includes(kw.toLowerCase())) {
        score += 2;
      }
    }
    for (const brand of pattern.typicalBrands) {
      if (content.includes(brand.toLowerCase())) {
        score += 3;
      }
    }
    return { pattern, score };
  });

  const relevant = scored
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, maxResults)
    .map(item => item.pattern);

  return relevant;
}
