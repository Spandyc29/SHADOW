import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

let supabaseInstance;

if (!supabaseUrl || !supabaseAnonKey) {
	// Provide a safe stub so the app doesn't crash in development when env vars are missing.
	console.warn("VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY not set. Supabase client will be a stub.");

	supabaseInstance = {
		auth: {
			getSession: async () => ({ data: { session: null } }),
			onAuthStateChange: (_cb) => ({ data: { subscription: { unsubscribe: () => {} } } }),
			signOut: async () => ({}),
			signInWithPassword: async () => ({ error: { message: "Supabase not configured" } }),
			signUp: async () => ({ error: { message: "Supabase not configured" } }),
		},
	};
} else {
	supabaseInstance = createClient(supabaseUrl, supabaseAnonKey);
}

export const supabase = supabaseInstance;
