-- ============================================================
-- DocSearch AI — Supabase RLS Security Fix
-- Run this entire script in: Supabase Dashboard → SQL Editor
-- ============================================================

-- ============================================================
-- STEP 1: Enable RLS on all three public tables
-- ============================================================

ALTER TABLE public.users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.query_history ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- STEP 2: Drop any old/conflicting policies (safe to run even if they don't exist)
-- ============================================================

DROP POLICY IF EXISTS "service_role_users"         ON public.users;
DROP POLICY IF EXISTS "service_role_documents"     ON public.documents;
DROP POLICY IF EXISTS "service_role_query_history" ON public.query_history;
DROP POLICY IF EXISTS "anon_no_access_users"       ON public.users;
DROP POLICY IF EXISTS "anon_no_access_documents"   ON public.documents;
DROP POLICY IF EXISTS "anon_no_access_history"     ON public.query_history;

-- ============================================================
-- STEP 3: Grant full access ONLY to service_role (your Flask backend)
-- The service_role key is used in app.py — it bypasses RLS by default,
-- but these explicit USING (true) policies make the intent clear and
-- satisfy the Supabase Advisor.
-- ============================================================

CREATE POLICY "service_role_users"
    ON public.users
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "service_role_documents"
    ON public.documents
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "service_role_query_history"
    ON public.query_history
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ============================================================
-- STEP 4: Explicitly DENY all access from anon and authenticated
-- roles (PostgREST API users). With RLS enabled and no permissive
-- policy for these roles, access is already denied — but we add
-- restrictive policies to be explicit and silence the advisor.
-- ============================================================

-- anon role: used by anyone hitting the Supabase REST API without a token
CREATE POLICY "anon_no_access_users"
    ON public.users
    AS RESTRICTIVE
    FOR ALL
    TO anon
    USING (false);

CREATE POLICY "anon_no_access_documents"
    ON public.documents
    AS RESTRICTIVE
    FOR ALL
    TO anon
    USING (false);

CREATE POLICY "anon_no_access_history"
    ON public.query_history
    AS RESTRICTIVE
    FOR ALL
    TO anon
    USING (false);

-- ============================================================
-- STEP 5: Revoke direct REST API access to the users table's
-- password column to fix the "Sensitive Columns Exposed" warning.
-- This prevents the password hash from ever being returned via
-- the Supabase REST API even if a policy somehow allows a row.
-- ============================================================

REVOKE SELECT (password) ON public.users FROM anon;
REVOKE SELECT (password) ON public.users FROM authenticated;

-- ============================================================
-- STEP 6: Verify — run these SELECTs to confirm RLS is ON
-- ============================================================

SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN ('users', 'documents', 'query_history');

-- Expected output:
--   tablename     | rowsecurity
--   --------------|------------
--   users         | t
--   documents     | t
--   query_history | t
