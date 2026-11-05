-- ASCTEMUN cloud persistence schema
-- Run this in the Supabase SQL Editor before using the cloud-enabled HTML app.

create table if not exists public.committees (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null default 'Committee Name',
  state jsonb not null default '{}'::jsonb,
  archived boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.committees enable row level security;

revoke all on table public.committees from anon, authenticated;
grant select, insert, update, delete on table public.committees to authenticated;

drop policy if exists "Users can view their committees" on public.committees;
create policy "Users can view their committees"
on public.committees
for select
to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "Users can create their committees" on public.committees;
create policy "Users can create their committees"
on public.committees
for insert
to authenticated
with check ((select auth.uid()) = user_id);

drop policy if exists "Users can update their committees" on public.committees;
create policy "Users can update their committees"
on public.committees
for update
to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

drop policy if exists "Users can delete their committees" on public.committees;
create policy "Users can delete their committees"
on public.committees
for delete
to authenticated
using ((select auth.uid()) = user_id);

create index if not exists committees_user_id_idx
on public.committees using btree (user_id);

create index if not exists committees_updated_at_idx
on public.committees using btree (updated_at desc);

create or replace function public.set_committee_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists committees_set_updated_at on public.committees;
create trigger committees_set_updated_at
before update on public.committees
for each row execute function public.set_committee_updated_at();
