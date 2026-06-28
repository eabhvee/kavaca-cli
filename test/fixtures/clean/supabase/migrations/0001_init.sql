-- Every table created here also enables Row Level Security. This is the
-- correct, locked-down setup the scanner should report as clean.

create table todos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  title text not null,
  done boolean default false
);

alter table todos enable row level security;

create policy "users read own todos" on todos
  for select using (auth.uid() = user_id);

create table public.profiles (
  id uuid primary key,
  display_name text
);

alter table public.profiles enable row level security;
