import { createClient } from "@supabase/supabase-js";

// Keys are read from the environment at runtime — never hard-coded.
const url = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;

export const supabase = createClient(url, anonKey);
