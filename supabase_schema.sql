-- ASCTEMUN multi-officer cloud schema
-- Run this in Supabase SQL Editor. This upgrades the original committees table
-- so multiple authenticated officers can share committees safely.

create extension if not exists pgcrypto;

create table if not exists public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'ASCTEMUN Organization',
  admin_user_id uuid not null unique references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.organization_members (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null unique references auth.users(id) on delete cascade,
  role text not null check (role in ('admin','officer')),
  display_name text,
  created_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);

create table if not exists public.officer_access (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  name text not null,
  position text not null,
  email text not null,
  user_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (organization_id, email)
);

alter table public.committees add column if not exists organization_id uuid references public.organizations(id) on delete cascade;

-- Backfill an organization for users who already have committees.
do $$
declare r record; org_id uuid;
begin
  for r in select distinct user_id from public.committees where organization_id is null loop
    select id into org_id from public.organizations where admin_user_id = r.user_id;
    if org_id is null then
      insert into public.organizations(admin_user_id) values (r.user_id) returning id into org_id;
      insert into public.organization_members(organization_id,user_id,role,display_name)
      values (org_id,r.user_id,'admin',null)
      on conflict (user_id) do nothing;
    end if;
    update public.committees set organization_id=org_id where user_id=r.user_id and organization_id is null;
  end loop;
end $$;

-- Secure helper functions for RLS.
create or replace function public.is_org_member(p_org uuid)
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists(
    select 1 from public.organization_members m
    where m.organization_id=p_org and m.user_id=auth.uid()
  );
$$;

create or replace function public.is_org_admin(p_org uuid)
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists(
    select 1 from public.organization_members m
    where m.organization_id=p_org and m.user_id=auth.uid() and m.role='admin'
  );
$$;

-- Creates an organization for a brand-new account, or returns the existing one.
create or replace function public.ensure_my_organization()
returns table(organization_id uuid, role text, display_name text)
language plpgsql security definer set search_path = public, auth
as $$
declare oid uuid; r text; dn text;
begin
  select m.organization_id, m.role, m.display_name
    into oid, r, dn
  from public.organization_members m
  where m.user_id=auth.uid()
  limit 1;

  if oid is null then
    insert into public.organizations(admin_user_id) values (auth.uid())
    returning id into oid;
    insert into public.organization_members(organization_id,user_id,role,display_name)
    values (oid,auth.uid(),'admin',null);
    update public.committees set organization_id=oid where user_id=auth.uid() and organization_id is null;
    r := 'admin';
  end if;

  return query select oid, r, dn;
end;
$$;

-- Administrator adds an officer. If the officer already has a Supabase account,
-- it is linked immediately; otherwise the auth trigger links it when they sign up.
create or replace function public.add_officer(
  p_name text, p_position text, p_email text
)
returns public.officer_access
language plpgsql security definer set search_path = public, auth
as $$
declare oid uuid; uid uuid; rec public.officer_access;
begin
  select m.organization_id into oid
  from public.organization_members m
  where m.user_id=auth.uid() and m.role='admin' limit 1;
  if oid is null then raise exception 'Only the organization administrator can add officers'; end if;
  select id into uid from auth.users where lower(email)=lower(trim(p_email)) limit 1;

  insert into public.officer_access(organization_id,name,position,email,user_id)
  values(oid,trim(p_name),trim(p_position),lower(trim(p_email)),uid)
  on conflict (organization_id,email) do update
    set name=excluded.name, position=excluded.position, user_id=coalesce(excluded.user_id, public.officer_access.user_id)
  returning * into rec;

  if uid is not null then
    insert into public.organization_members(organization_id,user_id,role,display_name)
    values(oid,uid,'officer',trim(p_name))
    on conflict(user_id) do update set organization_id=excluded.organization_id, role='officer', display_name=excluded.display_name;
  end if;
  return rec;
end;
$$;

create or replace function public.remove_officer(p_id uuid)
returns void
language plpgsql security definer set search_path = public, auth
as $$
declare oid uuid; uid uuid;
begin
  select organization_id,user_id into oid,uid from public.officer_access where id=p_id;
  if oid is null or not public.is_org_admin(oid) then
    raise exception 'Only the organization administrator can remove officers';
  end if;
  delete from public.organization_members where organization_id=oid and user_id=uid and role='officer';
  delete from public.officer_access where id=p_id;
end;
$$;

-- Link an officer when their email creates an account.
create or replace function public.link_officer_after_signup()
returns trigger
language plpgsql security definer set search_path = public, auth
as $$
declare r record;
begin
  for r in select id,organization_id,name from public.officer_access
           where lower(email)=lower(new.email) and user_id is null loop
    update public.officer_access set user_id=new.id where id=r.id;
    insert into public.organization_members(organization_id,user_id,role,display_name)
    values(r.organization_id,new.id,'officer',r.name)
    on conflict(user_id) do update set organization_id=excluded.organization_id, role='officer', display_name=excluded.display_name;
  end loop;
  return new;
end;
$$;

drop trigger if exists auth_user_links_officer on auth.users;
create trigger auth_user_links_officer
after insert on auth.users
for each row execute function public.link_officer_after_signup();

-- If a committee table was created by the original schema, make organization access authoritative.
alter table public.committees enable row level security;
revoke all on table public.committees from anon, authenticated;
grant select, insert, update, delete on table public.committees to authenticated;

drop policy if exists "Users can view their committees" on public.committees;
drop policy if exists "Users can create their committees" on public.committees;
drop policy if exists "Users can update their committees" on public.committees;
drop policy if exists "Users can delete their committees" on public.committees;

create policy "Organization members can view committees"
on public.committees for select to authenticated
using (public.is_org_member(organization_id) or user_id=auth.uid());

create policy "Organization members can create committees"
on public.committees for insert to authenticated
with check (public.is_org_member(organization_id) and user_id=auth.uid());

create policy "Organization members can update committees"
on public.committees for update to authenticated
using (public.is_org_member(organization_id) or user_id=auth.uid())
with check (public.is_org_member(organization_id) or user_id=auth.uid());

create policy "Only organization admins can delete committees"
on public.committees for delete to authenticated
using (public.is_org_admin(organization_id) or (organization_id is null and user_id=auth.uid()));

-- Officer/admin access table policies.
alter table public.officer_access enable row level security;
revoke all on table public.officer_access from anon, authenticated;
grant select on public.officer_access to authenticated;

drop policy if exists "Admins can view officer access" on public.officer_access;
create policy "Members can view their organization officers"
on public.officer_access for select to authenticated
using (public.is_org_member(organization_id));

-- Membership table policies.
alter table public.organization_members enable row level security;
revoke all on table public.organization_members from anon, authenticated;
grant select on public.organization_members to authenticated;

drop policy if exists "Members can view organization membership" on public.organization_members;
create policy "Members can view organization membership"
on public.organization_members for select to authenticated
using (public.is_org_member(organization_id));

grant execute on function public.ensure_my_organization() to authenticated;
grant execute on function public.add_officer(text,text,text) to authenticated;
grant execute on function public.remove_officer(uuid) to authenticated;

create index if not exists committees_organization_id_idx on public.committees(organization_id);
create index if not exists officer_access_org_idx on public.officer_access(organization_id);
create index if not exists organization_members_org_idx on public.organization_members(organization_id);

-- Updated timestamp trigger from the original schema.
create or replace function public.set_committee_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at=now(); return new; end; $$;
drop trigger if exists committees_set_updated_at on public.committees;
create trigger committees_set_updated_at before update on public.committees
for each row execute function public.set_committee_updated_at();

create table if not exists public.committee_notes (
  id uuid primary key default gen_random_uuid(),
  committee_id uuid not null references public.committees(id) on delete cascade,
  author_user_id uuid not null references auth.users(id) on delete cascade,
  author_name text not null,
  country_ids jsonb not null default '[]'::jsonb,
  countries jsonb not null default '[]'::jsonb,
  text text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.committee_notes enable row level security;
revoke all on table public.committee_notes from anon, authenticated;
grant select, insert, update, delete on table public.committee_notes to authenticated;

drop policy if exists "Members can view committee notes" on public.committee_notes;
create policy "Members can view committee notes"
on public.committee_notes for select to authenticated
using (exists(select 1 from public.committees c where c.id=committee_id and public.is_org_member(c.organization_id)));

drop policy if exists "Members can create committee notes" on public.committee_notes;
create policy "Members can create committee notes"
on public.committee_notes for insert to authenticated
with check (
  author_user_id=auth.uid() and
  exists(select 1 from public.committees c where c.id=committee_id and public.is_org_member(c.organization_id))
);

drop policy if exists "Authors and admins can update committee notes" on public.committee_notes;
create policy "Authors and admins can update committee notes"
on public.committee_notes for update to authenticated
using (
  author_user_id=auth.uid() or
  exists(select 1 from public.committees c where c.id=committee_id and public.is_org_admin(c.organization_id))
)
with check (
  author_user_id=auth.uid() or
  exists(select 1 from public.committees c where c.id=committee_id and public.is_org_admin(c.organization_id))
);

drop policy if exists "Authors and admins can delete committee notes" on public.committee_notes;
create policy "Authors and admins can delete committee notes"
on public.committee_notes for delete to authenticated
using (
  author_user_id=auth.uid() or
  exists(select 1 from public.committees c where c.id=committee_id and public.is_org_admin(c.organization_id))
);

create index if not exists committee_notes_committee_idx on public.committee_notes(committee_id, created_at);
create index if not exists committee_notes_author_idx on public.committee_notes(author_user_id);

create or replace function public.set_committee_note_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at=now(); return new; end; $$;
drop trigger if exists committee_notes_set_updated_at on public.committee_notes;
create trigger committee_notes_set_updated_at before update on public.committee_notes
for each row execute function public.set_committee_note_updated_at();

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public' and tablename='committees'
  ) then
    alter publication supabase_realtime add table public.committees;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime' and schemaname='public' and tablename='committee_notes'
  ) then
    alter publication supabase_realtime add table public.committee_notes;
  end if;
end $$;
