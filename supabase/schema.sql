-- NEON VAULT foundational marketplace schema
-- Run in Supabase SQL Editor for project Neonvault.
-- This creates database structure and baseline RLS. It does NOT configure a payment provider.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role text not null default 'buyer' check (role in ('buyer','seller','admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  seller_id uuid not null references auth.users(id) on delete restrict,
  title text not null check (char_length(title) between 3 and 160),
  slug text unique,
  description text not null default '',
  category text not null default 'other',
  price numeric(12,2) not null check (price >= 0),
  currency text not null default 'EUR' check (currency in ('EUR','USD','RUB')),
  status text not null default 'draft' check (status in ('draft','pending','active','hidden','rejected')),
  cover_path text,
  digital_file_path text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists products_status_category_idx on public.products(status, category);
create index if not exists products_seller_id_idx on public.products(seller_id);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  buyer_id uuid not null references auth.users(id) on delete restrict,
  status text not null default 'pending_payment'
    check (status in ('pending_payment','paid','fulfilled','completed','cancelled','refunded','disputed')),
  currency text not null default 'EUR' check (currency in ('EUR','USD','RUB')),
  subtotal numeric(12,2) not null default 0 check (subtotal >= 0),
  platform_fee numeric(12,2) not null default 0 check (platform_fee >= 0),
  total numeric(12,2) not null default 0 check (total >= 0),
  payment_provider text,
  payment_reference text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists orders_buyer_id_idx on public.orders(buyer_id);
create index if not exists orders_created_at_idx on public.orders(created_at desc);

create table if not exists public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  seller_id uuid not null references auth.users(id) on delete restrict,
  title_snapshot text not null,
  unit_price numeric(12,2) not null check (unit_price >= 0),
  digital_file_path_snapshot text,
  created_at timestamptz not null default now()
);

create index if not exists order_items_order_id_idx on public.order_items(order_id);
create index if not exists order_items_seller_id_idx on public.order_items(seller_id);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete cascade,
  buyer_id uuid not null references auth.users(id) on delete cascade,
  order_item_id uuid not null unique references public.order_items(id) on delete cascade,
  rating integer not null check (rating between 1 and 5),
  body text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.disputes (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  opened_by uuid not null references auth.users(id) on delete restrict,
  reason text not null,
  details text not null default '',
  status text not null default 'open' check (status in ('open','review','resolved','rejected','appeal')),
  resolution text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists disputes_status_idx on public.disputes(status);

-- Helper: a signed-in user is an admin only if explicitly inserted by the project owner.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.admin_users au where au.user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

alter table public.profiles enable row level security;
alter table public.admin_users enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.reviews enable row level security;
alter table public.disputes enable row level security;

drop policy if exists "Profiles readable by owner or admin" on public.profiles;
create policy "Profiles readable by owner or admin" on public.profiles
for select to authenticated using (id = (select auth.uid()) or (select public.is_admin()));

drop policy if exists "Users create own profile" on public.profiles;
create policy "Users create own profile" on public.profiles
for insert to authenticated with check (id = (select auth.uid()) and role in ('buyer','seller'));

drop policy if exists "Users update own profile" on public.profiles;
create policy "Users update own profile" on public.profiles
for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()) and role in ('buyer','seller'));

drop policy if exists "Admins read own membership" on public.admin_users;
create policy "Admins read own membership" on public.admin_users
for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists "Active products public readable" on public.products;
create policy "Active products public readable" on public.products
for select to anon, authenticated using (status = 'active' or seller_id = (select auth.uid()) or (select public.is_admin()));

drop policy if exists "Sellers create own products" on public.products;
create policy "Sellers create own products" on public.products
for insert to authenticated with check (seller_id = (select auth.uid()) and (select auth.uid()) is not null and not (select public.is_admin()));

drop policy if exists "Sellers update own products" on public.products;
create policy "Sellers update own products" on public.products
for update to authenticated using (seller_id = (select auth.uid()) or (select public.is_admin()))
with check ((seller_id = (select auth.uid()) and not (select public.is_admin())) or (select public.is_admin()));

drop policy if exists "Sellers delete own products or admins" on public.products;
create policy "Sellers delete own products or admins" on public.products
for delete to authenticated using (seller_id = (select auth.uid()) or (select public.is_admin()));

drop policy if exists "Buyers and admins read orders" on public.orders;
create policy "Buyers and admins read orders" on public.orders
for select to authenticated using (buyer_id = (select auth.uid()) or (select public.is_admin()));

drop policy if exists "Buyers create own pending orders" on public.orders;
create policy "Buyers create own pending orders" on public.orders
for insert to authenticated with check (
  buyer_id = (select auth.uid()) and status = 'pending_payment'
  and total >= 0 and subtotal >= 0 and platform_fee >= 0
);

drop policy if exists "Order items visible to buyer seller or admin" on public.order_items;
create policy "Order items visible to buyer seller or admin" on public.order_items
for select to authenticated using (
  seller_id = (select auth.uid())
  or (select public.is_admin())
  or exists (select 1 from public.orders o where o.id = order_id and o.buyer_id = (select auth.uid()))
);

drop policy if exists "Buyers read own reviews" on public.reviews;
create policy "Buyers read own reviews" on public.reviews
for select to anon, authenticated using (true);

drop policy if exists "Verified buyer creates review" on public.reviews;
create policy "Verified buyer creates review" on public.reviews
for insert to authenticated with check (
  buyer_id = (select auth.uid())
  and exists (
    select 1 from public.order_items oi
    join public.orders o on o.id = oi.order_id
    where oi.id = order_item_id and oi.product_id = product_id
      and o.buyer_id = (select auth.uid()) and o.status in ('paid','fulfilled','completed')
  )
);

drop policy if exists "Dispute visible to participants or admin" on public.disputes;
create policy "Dispute visible to participants or admin" on public.disputes
for select to authenticated using (
  opened_by = (select auth.uid())
  or (select public.is_admin())
  or exists (
    select 1 from public.orders o
    where o.id = order_id and o.buyer_id = (select auth.uid())
  )
  or exists (
    select 1 from public.order_items oi
    where oi.order_id = order_id and oi.seller_id = (select auth.uid())
  )
);

drop policy if exists "Buyer opens dispute on own order" on public.disputes;
create policy "Buyer opens dispute on own order" on public.disputes
for insert to authenticated with check (
  opened_by = (select auth.uid())
  and exists (select 1 from public.orders o where o.id = order_id and o.buyer_id = (select auth.uid()))
);

-- Intentionally no client-side insert/update policies for admin_users, payment status,
-- or dispute resolution. Those operations must be performed by trusted server-side code.
