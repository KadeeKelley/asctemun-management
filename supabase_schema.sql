-- ================================================================
-- ASCTEMUN
-- COMBINED SUPABASE SCHEMA + RLS + ACCOUNT DELETION MIGRATION
--
-- This script is designed to be safely rerun.
-- ================================================================


-- ================================================================
-- EXTENSIONS
-- ================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ================================================================
-- ORGANIZATIONS
-- ================================================================

CREATE TABLE IF NOT EXISTS public.organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL DEFAULT 'ASCTEMUN Organization',
  admin_user_id uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);


-- Existing databases may have been created without admin_user_id.

ALTER TABLE public.organizations
  ADD COLUMN IF NOT EXISTS admin_user_id uuid;


ALTER TABLE public.organizations
  ALTER COLUMN admin_user_id DROP NOT NULL;


-- Remove an old admin_user_id foreign key if one exists.

DO $$
DECLARE
  r record;
BEGIN

  FOR r IN
    SELECT c.conname
    FROM pg_constraint AS c
    JOIN pg_class AS t
      ON t.oid = c.conrelid
    JOIN pg_namespace AS tn
      ON tn.oid = t.relnamespace
    JOIN pg_class AS rt
      ON rt.oid = c.confrelid
    JOIN pg_namespace AS rn
      ON rn.oid = rt.relnamespace
    WHERE tn.nspname = 'public'
      AND t.relname = 'organizations'
      AND rn.nspname = 'auth'
      AND rt.relname = 'users'
      AND c.contype = 'f'
      AND pg_get_constraintdef(c.oid) ILIKE '%admin_user_id%'
  LOOP

    EXECUTE format(
      'ALTER TABLE public.organizations DROP CONSTRAINT IF EXISTS %I',
      r.conname
    );

  END LOOP;

END
$$;


ALTER TABLE public.organizations
  DROP CONSTRAINT IF EXISTS organizations_admin_user_id_fkey;


ALTER TABLE public.organizations
  ADD CONSTRAINT organizations_admin_user_id_fkey
  FOREIGN KEY (admin_user_id)
  REFERENCES auth.users(id)
  ON DELETE SET NULL;


CREATE UNIQUE INDEX IF NOT EXISTS organizations_admin_user_id_unique_idx
ON public.organizations(admin_user_id);


-- ================================================================
-- ORGANIZATION MEMBERS
-- ================================================================

CREATE TABLE IF NOT EXISTS public.organization_members (
  organization_id uuid NOT NULL
    REFERENCES public.organizations(id)
    ON DELETE CASCADE,

  user_id uuid NOT NULL
    REFERENCES auth.users(id)
    ON DELETE CASCADE,

  role text NOT NULL
    CHECK (role IN ('admin', 'officer')),

  display_name text,

  created_at timestamptz NOT NULL DEFAULT now(),

  PRIMARY KEY (organization_id, user_id)
);


-- The functions below use ON CONFLICT(user_id).
-- Make sure that uniqueness exists even on an older database.

CREATE UNIQUE INDEX IF NOT EXISTS organization_members_user_id_unique_idx
ON public.organization_members(user_id);


CREATE INDEX IF NOT EXISTS organization_members_org_idx
ON public.organization_members(organization_id);


-- ================================================================
-- OFFICER ACCESS
-- ================================================================

CREATE TABLE IF NOT EXISTS public.officer_access (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  organization_id uuid NOT NULL
    REFERENCES public.organizations(id)
    ON DELETE CASCADE,

  name text NOT NULL,

  position text NOT NULL,

  email text NOT NULL,

  user_id uuid
    REFERENCES auth.users(id)
    ON DELETE SET NULL,

  created_at timestamptz NOT NULL DEFAULT now()
);


CREATE UNIQUE INDEX IF NOT EXISTS officer_access_organization_email_unique_idx
ON public.officer_access(organization_id, email);


CREATE INDEX IF NOT EXISTS officer_access_org_idx
ON public.officer_access(organization_id);


-- ================================================================
-- COMMITTEES
-- ================================================================

ALTER TABLE public.committees
  ADD COLUMN IF NOT EXISTS organization_id uuid;


-- Make sure organization_id has the intended foreign key.

DO $$
DECLARE
  r record;
BEGIN

  FOR r IN
    SELECT c.conname
    FROM pg_constraint AS c
    JOIN pg_class AS t
      ON t.oid = c.conrelid
    JOIN pg_namespace AS tn
      ON tn.oid = t.relnamespace
    JOIN pg_class AS rt
      ON rt.oid = c.confrelid
    JOIN pg_namespace AS rn
      ON rn.oid = rt.relnamespace
    WHERE tn.nspname = 'public'
      AND t.relname = 'committees'
      AND rn.nspname = 'public'
      AND rt.relname = 'organizations'
      AND c.contype = 'f'
      AND pg_get_constraintdef(c.oid) ILIKE '%organization_id%'
  LOOP

    EXECUTE format(
      'ALTER TABLE public.committees DROP CONSTRAINT IF EXISTS %I',
      r.conname
    );

  END LOOP;

END
$$;


ALTER TABLE public.committees
  ADD CONSTRAINT committees_organization_id_fkey
  FOREIGN KEY (organization_id)
  REFERENCES public.organizations(id)
  ON DELETE CASCADE;


CREATE INDEX IF NOT EXISTS committees_organization_id_idx
ON public.committees(organization_id);


-- Make user_id nullable so committee history survives account deletion.

ALTER TABLE public.committees
  ALTER COLUMN user_id DROP NOT NULL;


-- ================================================================
-- BACKFILL ORGANIZATIONS FOR EXISTING COMMITTEES
-- ================================================================

DO $$
DECLARE
  r record;
  org_id uuid;
BEGIN

  FOR r IN
    SELECT DISTINCT user_id
    FROM public.committees
    WHERE organization_id IS NULL
      AND user_id IS NOT NULL
  LOOP

    SELECT id
    INTO org_id
    FROM public.organizations
    WHERE admin_user_id = r.user_id
    LIMIT 1;


    IF org_id IS NULL THEN

      INSERT INTO public.organizations (
        admin_user_id
      )
      VALUES (
        r.user_id
      )
      RETURNING id INTO org_id;


      INSERT INTO public.organization_members (
        organization_id,
        user_id,
        role,
        display_name
      )
      VALUES (
        org_id,
        r.user_id,
        'admin',
        NULL
      )
      ON CONFLICT (user_id)
      DO NOTHING;

    END IF;


    UPDATE public.committees
    SET organization_id = org_id
    WHERE user_id = r.user_id
      AND organization_id IS NULL;

  END LOOP;

END
$$;


-- ================================================================
-- HELPER FUNCTION: IS ORGANIZATION MEMBER
-- ================================================================

CREATE OR REPLACE FUNCTION public.is_org_member(
  p_org uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.organization_members AS m
    WHERE m.organization_id = p_org
      AND m.user_id = auth.uid()
  );
$$;


-- ================================================================
-- HELPER FUNCTION: IS ORGANIZATION ADMIN
-- ================================================================

CREATE OR REPLACE FUNCTION public.is_org_admin(
  p_org uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.organization_members AS m
    WHERE m.organization_id = p_org
      AND m.user_id = auth.uid()
      AND m.role = 'admin'
  );
$$;


-- ================================================================
-- ENSURE MY ORGANIZATION
-- ================================================================

CREATE OR REPLACE FUNCTION public.ensure_my_organization()
RETURNS TABLE (
  organization_id uuid,
  role text,
  display_name text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  oid uuid;
  r text;
  dn text;
BEGIN

  SELECT
    m.organization_id,
    m.role,
    m.display_name
  INTO
    oid,
    r,
    dn
  FROM public.organization_members AS m
  WHERE m.user_id = auth.uid()
  LIMIT 1;


  IF oid IS NULL THEN

    INSERT INTO public.organizations (
      admin_user_id
    )
    VALUES (
      auth.uid()
    )
    RETURNING id INTO oid;


    INSERT INTO public.organization_members (
      organization_id,
      user_id,
      role,
      display_name
    )
    VALUES (
      oid,
      auth.uid(),
      'admin',
      NULL
    )
    ON CONFLICT (user_id)
    DO UPDATE SET
      organization_id = EXCLUDED.organization_id,
      role = 'admin';


    UPDATE public.committees
    SET organization_id = oid
    WHERE user_id = auth.uid()
      AND organization_id IS NULL;


    r := 'admin';

  END IF;


  RETURN QUERY
  SELECT oid, r, dn;

END
$$;


-- ================================================================
-- ADD OFFICER
-- ================================================================

CREATE OR REPLACE FUNCTION public.add_officer(
  p_name text,
  p_position text,
  p_email text
)
RETURNS public.officer_access
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  oid uuid;
  uid uuid;
  rec public.officer_access;
BEGIN

  SELECT m.organization_id
  INTO oid
  FROM public.organization_members AS m
  WHERE m.user_id = auth.uid()
    AND m.role = 'admin'
  LIMIT 1;


  IF oid IS NULL THEN
    RAISE EXCEPTION
      'Only the organization administrator can add officers';
  END IF;


  SELECT id
  INTO uid
  FROM auth.users
  WHERE lower(email) = lower(trim(p_email))
  LIMIT 1;


  INSERT INTO public.officer_access (
    organization_id,
    name,
    position,
    email,
    user_id
  )
  VALUES (
    oid,
    trim(p_name),
    trim(p_position),
    lower(trim(p_email)),
    uid
  )
  ON CONFLICT (organization_id, email)
  DO UPDATE SET
    name = EXCLUDED.name,
    position = EXCLUDED.position,
    user_id = COALESCE(
      EXCLUDED.user_id,
      public.officer_access.user_id
    )
  RETURNING * INTO rec;


  IF uid IS NOT NULL THEN

    INSERT INTO public.organization_members (
      organization_id,
      user_id,
      role,
      display_name
    )
    VALUES (
      oid,
      uid,
      'officer',
      trim(p_name)
    )
    ON CONFLICT (user_id)
    DO UPDATE SET
      organization_id = EXCLUDED.organization_id,
      role = 'officer',
      display_name = EXCLUDED.display_name;

  END IF;


  RETURN rec;

END
$$;


-- ================================================================
-- REMOVE OFFICER
-- ================================================================

CREATE OR REPLACE FUNCTION public.remove_officer(
  p_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  oid uuid;
  uid uuid;
BEGIN

  SELECT
    organization_id,
    user_id
  INTO
    oid,
    uid
  FROM public.officer_access
  WHERE id = p_id;


  IF oid IS NULL
     OR NOT public.is_org_admin(oid)
  THEN
    RAISE EXCEPTION
      'Only the organization administrator can remove officers';
  END IF;


  DELETE FROM public.organization_members
  WHERE organization_id = oid
    AND user_id = uid
    AND role = 'officer';


  DELETE FROM public.officer_access
  WHERE id = p_id;

END
$$;


-- ================================================================
-- LINK OFFICER AFTER SIGNUP
-- ================================================================

CREATE OR REPLACE FUNCTION public.link_officer_after_signup()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  r record;
BEGIN

  FOR r IN
    SELECT
      id,
      organization_id,
      name
    FROM public.officer_access
    WHERE lower(email) = lower(NEW.email)
      AND user_id IS NULL
  LOOP

    UPDATE public.officer_access
    SET user_id = NEW.id
    WHERE id = r.id;


    INSERT INTO public.organization_members (
      organization_id,
      user_id,
      role,
      display_name
    )
    VALUES (
      r.organization_id,
      NEW.id,
      'officer',
      r.name
    )
    ON CONFLICT (user_id)
    DO UPDATE SET
      organization_id = EXCLUDED.organization_id,
      role = 'officer',
      display_name = EXCLUDED.display_name;

  END LOOP;


  RETURN NEW;

END
$$;


-- ================================================================
-- AUTH USER TRIGGER
-- ================================================================

DROP TRIGGER IF EXISTS auth_user_links_officer
ON auth.users;


CREATE TRIGGER auth_user_links_officer
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.link_officer_after_signup();


-- ================================================================
-- COMMITTEE UPDATED_AT
-- ================================================================

ALTER TABLE public.committees
  ADD COLUMN IF NOT EXISTS updated_at timestamptz
  DEFAULT now();


CREATE OR REPLACE FUNCTION public.set_committee_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


DROP TRIGGER IF EXISTS committees_set_updated_at
ON public.committees;


CREATE TRIGGER committees_set_updated_at
BEFORE UPDATE ON public.committees
FOR EACH ROW
EXECUTE FUNCTION public.set_committee_updated_at();


-- ================================================================
-- COMMITTEE RLS
-- ================================================================

ALTER TABLE public.committees
ENABLE ROW LEVEL SECURITY;


REVOKE ALL
ON TABLE public.committees
FROM anon, authenticated;


GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE public.committees
TO authenticated;


-- Remove every known previous policy name.

DROP POLICY IF EXISTS "Users can view their committees"
ON public.committees;

DROP POLICY IF EXISTS "Users can create their committees"
ON public.committees;

DROP POLICY IF EXISTS "Users can update their committees"
ON public.committees;

DROP POLICY IF EXISTS "Users can delete their committees"
ON public.committees;

DROP POLICY IF EXISTS "Organization members can view committees"
ON public.committees;

DROP POLICY IF EXISTS "Organization members can create committees"
ON public.committees;

DROP POLICY IF EXISTS "Organization members can update committees"
ON public.committees;

DROP POLICY IF EXISTS "Only organization admins can delete committees"
ON public.committees;


CREATE POLICY "Organization members can view committees"
ON public.committees
FOR SELECT
TO authenticated
USING (
  public.is_org_member(organization_id)
  OR user_id = auth.uid()
);


CREATE POLICY "Organization members can create committees"
ON public.committees
FOR INSERT
TO authenticated
WITH CHECK (
  public.is_org_member(organization_id)
  AND user_id = auth.uid()
);


CREATE POLICY "Organization members can update committees"
ON public.committees
FOR UPDATE
TO authenticated
USING (
  public.is_org_member(organization_id)
  OR user_id = auth.uid()
)
WITH CHECK (
  public.is_org_member(organization_id)
  OR user_id = auth.uid()
);


CREATE POLICY "Only organization admins can delete committees"
ON public.committees
FOR DELETE
TO authenticated
USING (
  public.is_org_admin(organization_id)
  OR (
    organization_id IS NULL
    AND user_id = auth.uid()
  )
);


-- ================================================================
-- OFFICER ACCESS RLS
-- ================================================================

ALTER TABLE public.officer_access
ENABLE ROW LEVEL SECURITY;


REVOKE ALL
ON TABLE public.officer_access
FROM anon, authenticated;


GRANT SELECT
ON TABLE public.officer_access
TO authenticated;


DROP POLICY IF EXISTS "Admins can view officer access"
ON public.officer_access;

DROP POLICY IF EXISTS "Members can view their organization officers"
ON public.officer_access;


CREATE POLICY "Members can view their organization officers"
ON public.officer_access
FOR SELECT
TO authenticated
USING (
  public.is_org_member(organization_id)
);


-- ================================================================
-- ORGANIZATION MEMBERS RLS
-- ================================================================

ALTER TABLE public.organization_members
ENABLE ROW LEVEL SECURITY;


REVOKE ALL
ON TABLE public.organization_members
FROM anon, authenticated;


GRANT SELECT
ON TABLE public.organization_members
TO authenticated;


DROP POLICY IF EXISTS "Members can view organization membership"
ON public.organization_members;


CREATE POLICY "Members can view organization membership"
ON public.organization_members
FOR SELECT
TO authenticated
USING (
  public.is_org_member(organization_id)
);


-- ================================================================
-- FUNCTION PERMISSIONS
-- ================================================================

GRANT EXECUTE
ON FUNCTION public.ensure_my_organization()
TO authenticated;


GRANT EXECUTE
ON FUNCTION public.add_officer(text, text, text)
TO authenticated;


GRANT EXECUTE
ON FUNCTION public.remove_officer(uuid)
TO authenticated;


-- ================================================================
-- COMMITTEE NOTES
-- ================================================================

CREATE TABLE IF NOT EXISTS public.committee_notes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  committee_id uuid NOT NULL
    REFERENCES public.committees(id)
    ON DELETE CASCADE,

  author_user_id uuid
    REFERENCES auth.users(id)
    ON DELETE SET NULL,

  author_name text NOT NULL,

  country_ids jsonb NOT NULL
    DEFAULT '[]'::jsonb,

  countries jsonb NOT NULL
    DEFAULT '[]'::jsonb,

  text text NOT NULL,

  created_at timestamptz NOT NULL
    DEFAULT now(),

  updated_at timestamptz NOT NULL
    DEFAULT now()
);


-- Existing versions may have author_user_id as NOT NULL.

ALTER TABLE public.committee_notes
  ADD COLUMN IF NOT EXISTS author_user_id uuid;


ALTER TABLE public.committee_notes
  ALTER COLUMN author_user_id DROP NOT NULL;


-- ================================================================
-- COMMITTEE NOTES FOREIGN KEY
-- ================================================================

DO $$
DECLARE
  r record;
BEGIN

  FOR r IN
    SELECT c.conname
    FROM pg_constraint AS c
    JOIN pg_class AS t
      ON t.oid = c.conrelid
    JOIN pg_namespace AS tn
      ON tn.oid = t.relnamespace
    JOIN pg_class AS rt
      ON rt.oid = c.confrelid
    JOIN pg_namespace AS rn
      ON rn.oid = rt.relnamespace
    WHERE tn.nspname = 'public'
      AND t.relname = 'committee_notes'
      AND rn.nspname = 'auth'
      AND rt.relname = 'users'
      AND c.contype = 'f'
      AND pg_get_constraintdef(c.oid) ILIKE '%author_user_id%'
  LOOP

    EXECUTE format(
      'ALTER TABLE public.committee_notes DROP CONSTRAINT IF EXISTS %I',
      r.conname
    );

  END LOOP;

END
$$;


ALTER TABLE public.committee_notes
  DROP CONSTRAINT IF EXISTS committee_notes_author_user_id_fkey;


ALTER TABLE public.committee_notes
  ADD CONSTRAINT committee_notes_author_user_id_fkey
  FOREIGN KEY (author_user_id)
  REFERENCES auth.users(id)
  ON DELETE SET NULL;


-- ================================================================
-- COMMITTEE NOTES RLS
-- ================================================================

ALTER TABLE public.committee_notes
ENABLE ROW LEVEL SECURITY;


REVOKE ALL
ON TABLE public.committee_notes
FROM anon, authenticated;


GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE public.committee_notes
TO authenticated;


DROP POLICY IF EXISTS "Members can view committee notes"
ON public.committee_notes;


DROP POLICY IF EXISTS "Members can create committee notes"
ON public.committee_notes;


DROP POLICY IF EXISTS "Authors and admins can update committee notes"
ON public.committee_notes;


DROP POLICY IF EXISTS "Authors and admins can delete committee notes"
ON public.committee_notes;


CREATE POLICY "Members can view committee notes"
ON public.committee_notes
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM public.committees AS c
    WHERE c.id = public.committee_notes.committee_id
      AND public.is_org_member(c.organization_id)
  )
);


CREATE POLICY "Members can create committee notes"
ON public.committee_notes
FOR INSERT
TO authenticated
WITH CHECK (
  author_user_id = auth.uid()
  AND EXISTS (
    SELECT 1
    FROM public.committees AS c
    WHERE c.id = public.committee_notes.committee_id
      AND public.is_org_member(c.organization_id)
  )
);


CREATE POLICY "Authors and admins can update committee notes"
ON public.committee_notes
FOR UPDATE
TO authenticated
USING (
  author_user_id = auth.uid()
  OR EXISTS (
    SELECT 1
    FROM public.committees AS c
    WHERE c.id = public.committee_notes.committee_id
      AND public.is_org_admin(c.organization_id)
  )
)
WITH CHECK (
  author_user_id = auth.uid()
  OR EXISTS (
    SELECT 1
    FROM public.committees AS c
    WHERE c.id = public.committee_notes.committee_id
      AND public.is_org_admin(c.organization_id)
  )
);


CREATE POLICY "Authors and admins can delete committee notes"
ON public.committee_notes
FOR DELETE
TO authenticated
USING (
  author_user_id = auth.uid()
  OR EXISTS (
    SELECT 1
    FROM public.committees AS c
    WHERE c.id = public.committee_notes.committee_id
      AND public.is_org_admin(c.organization_id)
  )
);


-- ================================================================
-- COMMITTEE NOTES INDEXES
-- ================================================================

CREATE INDEX IF NOT EXISTS committee_notes_committee_idx
ON public.committee_notes(committee_id, created_at);


CREATE INDEX IF NOT EXISTS committee_notes_author_idx
ON public.committee_notes(author_user_id);


-- ================================================================
-- COMMITTEE NOTES UPDATED_AT
-- ================================================================

CREATE OR REPLACE FUNCTION public.set_committee_note_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


DROP TRIGGER IF EXISTS committee_notes_set_updated_at
ON public.committee_notes;


CREATE TRIGGER committee_notes_set_updated_at
BEFORE UPDATE ON public.committee_notes
FOR EACH ROW
EXECUTE FUNCTION public.set_committee_note_updated_at();


-- ================================================================
-- SUPABASE REALTIME
-- ================================================================

DO $$
BEGIN

  IF EXISTS (
    SELECT 1
    FROM pg_publication
    WHERE pubname = 'supabase_realtime'
  ) THEN

    IF NOT EXISTS (
      SELECT 1
      FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
        AND tablename = 'committees'
    ) THEN

      ALTER PUBLICATION supabase_realtime
      ADD TABLE public.committees;

    END IF;


    IF NOT EXISTS (
      SELECT 1
      FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
        AND tablename = 'committee_notes'
    ) THEN

      ALTER PUBLICATION supabase_realtime
      ADD TABLE public.committee_notes;

    END IF;

  END IF;

END
$$;


-- ================================================================
-- ACCOUNT DELETION
--
-- Keep historical organizations, committees and notes.
-- Remove the deleted user's authentication identity and
-- personal membership/access links.
-- ================================================================


-- ================================================================
-- ORGANIZATIONS -> AUTH.USERS
-- ON DELETE SET NULL
-- ================================================================

ALTER TABLE public.organizations
  ALTER COLUMN admin_user_id DROP NOT NULL;


DO $$
DECLARE
  r record;
BEGIN

  FOR r IN
    SELECT c.conname
    FROM pg_constraint AS c
    JOIN pg_class AS t
      ON t.oid = c.conrelid
    JOIN pg_namespace AS tn
      ON tn.oid = t.relnamespace
    JOIN pg_class AS rt
      ON rt.oid = c.confrelid
    JOIN pg_namespace AS rn
      ON rn.oid = rt.relnamespace
    WHERE tn.nspname = 'public'
      AND t.relname = 'organizations'
      AND rn.nspname = 'auth'
      AND rt.relname = 'users'
      AND c.contype = 'f'
      AND pg_get_constraintdef(c.oid) ILIKE '%admin_user_id%'
  LOOP

    EXECUTE format(
      'ALTER TABLE public.organizations DROP CONSTRAINT IF EXISTS %I',
      r.conname
    );

  END LOOP;

END
$$;


ALTER TABLE public.organizations
  DROP CONSTRAINT IF EXISTS organizations_admin_user_id_fkey;


ALTER TABLE public.organizations
  ADD CONSTRAINT organizations_admin_user_id_fkey
  FOREIGN KEY (admin_user_id)
  REFERENCES auth.users(id)
  ON DELETE SET NULL;


-- ================================================================
-- COMMITTEES -> AUTH.USERS
-- ON DELETE SET NULL
-- ================================================================

ALTER TABLE public.committees
  ALTER COLUMN user_id DROP NOT NULL;


DO $$
DECLARE
  r record;
BEGIN

  FOR r IN
    SELECT c.conname
    FROM pg_constraint AS c
    JOIN pg_class AS t
      ON t.oid = c.conrelid
    JOIN pg_namespace AS tn
      ON tn.oid = t.relnamespace
    JOIN pg_class AS rt
      ON rt.oid = c.confrelid
    JOIN pg_namespace AS rn
      ON rn.oid = rt.relnamespace
    WHERE tn.nspname = 'public'
      AND t.relname = 'committees'
      AND rn.nspname = 'auth'
      AND rt.relname = 'users'
      AND c.contype = 'f'
      AND pg_get_constraintdef(c.oid) ILIKE '%user_id%'
  LOOP

    EXECUTE format(
      'ALTER TABLE public.committees DROP CONSTRAINT IF EXISTS %I',
      r.conname
    );

  END LOOP;

END
$$;


ALTER TABLE public.committees
  DROP CONSTRAINT IF EXISTS committees_user_id_auth_users_fkey;


ALTER TABLE public.committees
  ADD CONSTRAINT committees_user_id_auth_users_fkey
  FOREIGN KEY (user_id)
  REFERENCES auth.users(id)
  ON DELETE SET NULL;


-- ================================================================
-- DELETE MY ACCOUNT
-- ================================================================

CREATE OR REPLACE FUNCTION public.delete_my_account()
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
  uid uuid := auth.uid();
BEGIN

  IF uid IS NULL THEN
    RAISE EXCEPTION
      'You must be signed in to delete your account';
  END IF;


  -- Remove personal organization membership.

  DELETE FROM public.organization_members
  WHERE user_id = uid;


  -- Keep officer access history but unlink the account.

  UPDATE public.officer_access
  SET user_id = NULL
  WHERE user_id = uid;


  -- Keep committees but remove the deleted user's ownership link.

  UPDATE public.committees
  SET user_id = NULL
  WHERE user_id = uid;


  -- Keep organizations but remove the deleted administrator.

  UPDATE public.organizations
  SET admin_user_id = NULL
  WHERE admin_user_id = uid;


  -- Keep historical notes but unlink the deleted author.

  UPDATE public.committee_notes
  SET author_user_id = NULL
  WHERE author_user_id = uid;


  -- Finally delete the authentication account.

  DELETE FROM auth.users
  WHERE id = uid;


  RETURN true;

END
$$;


-- ================================================================
-- DELETE ACCOUNT FUNCTION PERMISSIONS
-- ================================================================

REVOKE ALL
ON FUNCTION public.delete_my_account()
FROM public, anon;


GRANT EXECUTE
ON FUNCTION public.delete_my_account()
TO authenticated;
