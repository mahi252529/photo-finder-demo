-- Wedding Photo Finder demo: guest activity log + private selfies
-- Guests sign in anonymously; they can add and update only their own row and selfie.
-- Only users listed in public.admins can read everyone's rows and selfies.

create table if not exists public.admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.guest_log (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  event_slug text not null default 'sneha-karthik',
  name text not null check (char_length(name) between 2 and 60),
  phone text check (phone is null or char_length(phone) <= 15),
  matched int not null default 0 check (matched >= 0),
  downloads int[] not null default '{}',
  selfie_path text,
  deleted boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.admins enable row level security;
alter table public.guest_log enable row level security;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.admins a where a.user_id = auth.uid());
$$;

drop policy if exists "admins read own row" on public.admins;
create policy "admins read own row" on public.admins
  for select to authenticated using (user_id = auth.uid());

drop policy if exists "guest inserts own row" on public.guest_log;
create policy "guest inserts own row" on public.guest_log
  for insert to authenticated with check (user_id = auth.uid());

drop policy if exists "guest updates own row" on public.guest_log;
create policy "guest updates own row" on public.guest_log
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists "guest reads own row, admin reads all" on public.guest_log;
create policy "guest reads own row, admin reads all" on public.guest_log
  for select to authenticated using (user_id = auth.uid() or public.is_admin());

drop policy if exists "admin deletes rows" on public.guest_log;
create policy "admin deletes rows" on public.guest_log
  for delete to authenticated using (public.is_admin());

-- Private bucket for selfies, 2 MB max, images only
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('selfies', 'selfies', false, 2097152, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "guest uploads own selfie" on storage.objects;
create policy "guest uploads own selfie" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'selfies' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "guest updates own selfie" on storage.objects;
create policy "guest updates own selfie" on storage.objects
  for update to authenticated
  using (bucket_id = 'selfies' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "owner or admin reads selfie" on storage.objects;
create policy "owner or admin reads selfie" on storage.objects
  for select to authenticated
  using (bucket_id = 'selfies' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));

drop policy if exists "owner or admin deletes selfie" on storage.objects;
create policy "owner or admin deletes selfie" on storage.objects
  for delete to authenticated
  using (bucket_id = 'selfies' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));

-- Live updates on the admin dashboard (Realtime respects the policies above)
do $$ begin
  alter publication supabase_realtime add table public.guest_log;
exception when duplicate_object then null; end $$;
