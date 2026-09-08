-- ==============================================================================
-- PhishGuard — Production PostgreSQL Migration (Supabase)
-- Version: 20260906000000_phishguard_schema.sql
-- Description: Core tables for scans and flagged indicators with strict RLS
-- ==============================================================================

-- Enable UUID extension if not enabled
create extension if not exists "uuid-ossp";

-- 1. Scans Table
create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  created_at timestamptz default now() not null,
  subject text,
  sender text,
  risk_score int check (risk_score between 0 and 100) not null,
  verdict text check (verdict in ('safe', 'suspicious', 'phishing')) not null,
  tactics_detected text[] default '{}'::text[],
  explanation text,
  safe_summary text,
  ai_provider text default 'claude'
);

-- 2. Flagged Indicators Table
create table if not exists public.flagged_indicators (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid references public.scans(id) on delete cascade not null,
  indicator_type text not null,
  detail text not null,
  created_at timestamptz default now() not null
);

-- 3. Indexes for fast user queries and time-series analytics
create index if not exists idx_scans_user_id on public.scans(user_id);
create index if not exists idx_scans_created_at on public.scans(created_at desc);
create index if not exists idx_scans_verdict on public.scans(verdict);
create index if not exists idx_flagged_indicators_scan_id on public.flagged_indicators(scan_id);

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES — NON-NEGOTIABLE SECURITY CONTROLS
-- ==============================================================================

-- Enable RLS on all tables containing user information
alter table public.scans enable row level security;
alter table public.flagged_indicators enable row level security;

-- Drop any existing policies to ensure clean idempotent migrations
drop policy if exists "Users can only see their own scans" on public.scans;
drop policy if exists "Users can only insert their own scans" on public.scans;
drop policy if exists "Users can only delete their own scans" on public.scans;

drop policy if exists "Users can only see indicators for their own scans" on public.flagged_indicators;
drop policy if exists "Users can only insert indicators for their own scans" on public.flagged_indicators;
drop policy if exists "Users can only delete indicators for their own scans" on public.flagged_indicators;

-- Policies for public.scans:
-- Users can only view scans belonging to their authenticated UID
create policy "Users can only see their own scans"
  on public.scans
  for select
  using (auth.uid() = user_id);

-- Users can only insert scans where user_id matches their authenticated UID
create policy "Users can only insert their own scans"
  on public.scans
  for insert
  with check (auth.uid() = user_id);

-- Users can delete their own scans
create policy "Users can only delete their own scans"
  on public.scans
  for delete
  using (auth.uid() = user_id);

-- Policies for public.flagged_indicators:
-- Users can only view indicators linked to scans they own
create policy "Users can only see indicators for their own scans"
  on public.flagged_indicators
  for select
  using (
    exists (
      select 1 from public.scans
      where public.scans.id = public.flagged_indicators.scan_id
      and public.scans.user_id = auth.uid()
    )
  );

-- Users can only insert indicators linked to scans they own
create policy "Users can only insert indicators for their own scans"
  on public.flagged_indicators
  for insert
  with check (
    exists (
      select 1 from public.scans
      where public.scans.id = public.flagged_indicators.scan_id
      and public.scans.user_id = auth.uid()
    )
  );

-- Users can delete indicators linked to scans they own
create policy "Users can only delete indicators for their own scans"
  on public.flagged_indicators
  for delete
  using (
    exists (
      select 1 from public.scans
      where public.scans.id = public.flagged_indicators.scan_id
      and public.scans.user_id = auth.uid()
    )
  );
