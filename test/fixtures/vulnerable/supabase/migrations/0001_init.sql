-- PLANTED VULN: the `orders` table never enables Row Level Security, so anyone
-- holding the anon key can read every order. `profiles` is correctly locked.

create table orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  total_cents integer not null,
  card_last4 text
);

create table profiles (
  id uuid primary key,
  display_name text
);

alter table profiles enable row level security;
