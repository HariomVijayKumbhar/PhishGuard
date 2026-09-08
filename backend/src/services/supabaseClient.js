import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

let clientInstance = null;

/**
 * Initialize or get the Supabase admin client (using service role key)
 */
export function getSupabaseAdmin() {
  if (clientInstance) {
    return clientInstance;
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey || supabaseUrl.includes('your-project')) {
    return null;
  }

  clientInstance = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  });

  return clientInstance;
}

/**
 * For testing: set or mock the client instance
 */
export function setSupabaseAdmin(mockClient) {
  clientInstance = mockClient;
}

/**
 * Check if Supabase credentials are configured
 */
export function isSupabaseConfigured() {
  return Boolean(getSupabaseAdmin());
}

// In-memory user store for dev fallback when Supabase is unconfigured
const devUsersStore = new Map();

/**
 * Register a new user with email and password
 */
export async function signUpUser({ email, password }) {
  const supabase = getSupabaseAdmin();
  if (!supabase) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Supabase client is not configured on the backend');
    }
    // Dev fallback
    if (devUsersStore.has(email)) {
      throw new Error('User already registered with this email');
    }
    const fakeId = `dev_user_${Date.now().toString(36)}`;
    const devUser = {
      id: fakeId,
      email,
      created_at: new Date().toISOString(),
      app_metadata: { provider: 'email' },
      user_metadata: {}
    };
    devUsersStore.set(email, { user: devUser, password });
    const token = `dev_token_${Buffer.from(JSON.stringify({ user: devUser, exp: Date.now() + 86400000 })).toString('base64')}`;
    return {
      user: devUser,
      session: {
        access_token: token,
        token_type: 'bearer',
        expires_in: 86400
      }
    };
  }

  // 1. Create confirmed user via Supabase admin API
  const { data: created, error: createError } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true
  });

  if (createError) {
    throw new Error(createError.message);
  }

  // 2. Sign in to obtain session JWT
  const { data: sessionData, error: sessionError } = await supabase.auth.signInWithPassword({
    email,
    password
  });

  if (sessionError) {
    return {
      user: created.user,
      session: null
    };
  }

  return {
    user: sessionData.user,
    session: sessionData.session
  };
}

/**
 * Sign in existing user with email and password
 */
export async function signInUser({ email, password }) {
  const supabase = getSupabaseAdmin();
  if (!supabase) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Supabase client is not configured on the backend');
    }
    // Dev fallback
    const stored = devUsersStore.get(email);
    if (!stored || stored.password !== password) {
      throw new Error('Invalid email or password');
    }
    const token = `dev_token_${Buffer.from(JSON.stringify({ user: stored.user, exp: Date.now() + 86400000 })).toString('base64')}`;
    return {
      user: stored.user,
      session: {
        access_token: token,
        token_type: 'bearer',
        expires_in: 86400
      }
    };
  }

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password
  });

  if (error || !data?.user || !data?.session) {
    throw new Error(error?.message || 'Invalid email or password');
  }

  return {
    user: data.user,
    session: data.session
  };
}

/**
 * Verify Supabase JWT token and return the authenticated user
 */
export async function verifyUserToken(jwtToken) {
  if (!jwtToken) {
    throw new Error('Missing authentication token');
  }

  // Support local dev tokens when Supabase is not configured in development
  if (jwtToken.startsWith('dev_token_') && process.env.NODE_ENV !== 'production') {
    try {
      const raw = Buffer.from(jwtToken.replace('dev_token_', ''), 'base64').toString('utf-8');
      const payload = JSON.parse(raw);
      if (payload.exp && Date.now() > payload.exp) {
        throw new Error('Dev token expired');
      }
      return payload.user;
    } catch {
      throw new Error('Invalid development authentication token');
    }
  }

  const supabase = getSupabaseAdmin();
  if (!supabase) {
    throw new Error('Supabase client is not configured on the backend');
  }

  const { data, error } = await supabase.auth.getUser(jwtToken);
  if (error || !data?.user) {
    throw new Error(error?.message || 'Invalid or expired authentication token');
  }

  return data.user;
}

/**
 * Save scan result and any flagged indicators to the database
 */
export async function saveScanRecord({
  userId,
  subject,
  sender,
  riskScore,
  verdict,
  tacticsDetected = [],
  explanation,
  safeSummary,
  aiProvider = 'claude',
  indicators = []
}) {
  const supabase = getSupabaseAdmin();
  if (!supabase) {
    return null;
  }

  // 1. Insert scan record
  const { data: scan, error: scanError } = await supabase
    .from('scans')
    .insert({
      user_id: userId,
      subject: subject || '(No Subject)',
      sender: sender || 'Unknown',
      risk_score: riskScore,
      verdict,
      tactics_detected: tacticsDetected,
      explanation,
      safe_summary: safeSummary,
      ai_provider: aiProvider
    })
    .select()
    .single();

  if (scanError) {
    throw new Error(`Failed to save scan record: ${scanError.message}`);
  }

  // 2. Insert flagged indicators if any
  if (indicators.length > 0 && scan?.id) {
    const indicatorRows = indicators.map(ind => ({
      scan_id: scan.id,
      indicator_type: ind.type || ind.indicator_type || 'heuristic_warning',
      detail: typeof ind === 'string' ? ind : (ind.detail || ind.description || JSON.stringify(ind))
    }));

    const { error: indError } = await supabase
      .from('flagged_indicators')
      .insert(indicatorRows);

    if (indError) {
      console.warn(`[Supabase] Warning: Failed to insert indicators for scan ${scan.id}:`, indError.message);
    }
  }

  return scan;
}

/**
 * Get scan history for a specific user
 */
export async function getUserScans(userId, { limit = 50, offset = 0 } = {}) {
  const supabase = getSupabaseAdmin();
  if (!supabase) {
    return { scans: [], total: 0 };
  }

  const { data, error, count } = await supabase
    .from('scans')
    .select('*', { count: 'exact' })
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    throw new Error(`Failed to fetch user scans: ${error.message}`);
  }

  return { scans: data || [], total: count || 0 };
}

/**
 * Get detailed scan by ID including its flagged indicators
 */
export async function getScanById(scanId, userId) {
  const supabase = getSupabaseAdmin();
  if (!supabase) {
    return null;
  }

  const { data: scan, error: scanError } = await supabase
    .from('scans')
    .select('*')
    .eq('id', scanId)
    .eq('user_id', userId)
    .single();

  if (scanError || !scan) {
    return null;
  }

  const { data: indicators } = await supabase
    .from('flagged_indicators')
    .select('*')
    .eq('scan_id', scanId)
    .order('created_at', { ascending: true });

  return {
    ...scan,
    indicators: indicators || []
  };
}

/**
 * Calculate aggregated metrics for the user's dashboard
 */
export async function getUserMetrics(userId) {
  const supabase = getSupabaseAdmin();
  if (!supabase) {
    return {
      total_scans: 0,
      phishing_detected: 0,
      suspicious_detected: 0,
      safe_detected: 0,
      average_risk_score: 0,
      top_tactics: []
    };
  }

  const { data: scans, error } = await supabase
    .from('scans')
    .select('risk_score, verdict, tactics_detected, created_at')
    .eq('user_id', userId);

  if (error) {
    throw new Error(`Failed to calculate metrics: ${error.message}`);
  }

  const total = scans?.length || 0;
  if (total === 0) {
    return {
      total_scans: 0,
      phishing_detected: 0,
      suspicious_detected: 0,
      safe_detected: 0,
      average_risk_score: 0,
      top_tactics: []
    };
  }

  let phishingCount = 0;
  let suspiciousCount = 0;
  let safeCount = 0;
  let totalScore = 0;
  const tacticsMap = {};

  for (const scan of scans) {
    if (scan.verdict === 'phishing') phishingCount++;
    else if (scan.verdict === 'suspicious') suspiciousCount++;
    else if (scan.verdict === 'safe') safeCount++;

    totalScore += scan.risk_score || 0;

    if (Array.isArray(scan.tactics_detected)) {
      for (const tactic of scan.tactics_detected) {
        tacticsMap[tactic] = (tacticsMap[tactic] || 0) + 1;
      }
    }
  }

  const topTactics = Object.entries(tacticsMap)
    .map(([tactic, count]) => ({ tactic, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  return {
    total_scans: total,
    phishing_detected: phishingCount,
    suspicious_detected: suspiciousCount,
    safe_detected: safeCount,
    average_risk_score: Math.round(totalScore / total),
    top_tactics: topTactics
  };
}
