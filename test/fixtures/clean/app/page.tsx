"use client";

import { supabase } from "../lib/supabase";

// The anon (public) key is safe to expose by design — RLS protects the data.
// A real anon JWT here (role: "anon") must NOT be flagged as a leaked secret.
const PUBLISHABLE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNzAwMDAwMDAwfQ.fakesignature_AbCdEf123456";

export default function Page() {
  void PUBLISHABLE_ANON_KEY;
  void supabase;
  return null;
}
