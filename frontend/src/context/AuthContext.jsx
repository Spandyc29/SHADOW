import { createContext, useContext, useEffect, useState } from "react";
import { supabase } from "../supabaseClient";

const AuthContext = createContext();

const GUEST_SCAN_LIMIT = 3;

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isGuest, setIsGuest] = useState(false);
  const [guestScanCount, setGuestScanCount] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check active session on initialization
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session) {
        setUser(session.user);
        setIsGuest(false);
      }
      setLoading(false);
    });

    // Listen for real-time auth changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) {
        setUser(session.user);
        setIsGuest(false);
      } else {
        setUser(null);
      }
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  const loginAsGuest = () => {
    setUser(null);
    setIsGuest(true);
    setGuestScanCount(0);
  };

  const incrementGuestScanCount = () => {
    setGuestScanCount((prev) => prev + 1);
  };

  const logout = async () => {
    await supabase.auth.signOut();
    setUser(null);
    setIsGuest(false);
    setGuestScanCount(0);
  };

  const hasReachedGuestLimit = isGuest && guestScanCount >= GUEST_SCAN_LIMIT;

  return (
    <AuthContext.Provider
      value={{
        user,
        isGuest,
        guestScanCount,
        guestScanLimit: GUEST_SCAN_LIMIT,
        hasReachedGuestLimit,
        incrementGuestScanCount,
        loading,
        loginAsGuest,
        logout,
        setUser,
      }}
    >
      {!loading && children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext) || {};