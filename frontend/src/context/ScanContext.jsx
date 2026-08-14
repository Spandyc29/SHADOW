import React, { createContext, useContext, useState, useCallback, useMemo } from 'react';

const ScanContext = createContext({
  scanContext: null,
  setScanContext: () => {},
  clearScanContext: () => {},
});

export function ScanContextProvider({ children }) {
  const [scanContext, setScanContextState] = useState(null);

  const setScanContext = useCallback((contextData) => {
    setScanContextState((prev) => {
      if (contextData === prev) return prev;
      if (prev && contextData && JSON.stringify(prev) === JSON.stringify(contextData)) {
        return prev;
      }
      return contextData;
    });
  }, []);

  const clearScanContext = useCallback(() => {
    setScanContextState((prev) => (prev === null ? null : null));
  }, []);

  const value = useMemo(
    () => ({ scanContext, setScanContext, clearScanContext }),
    [scanContext, setScanContext, clearScanContext]
  );

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScanContext() {
  return useContext(ScanContext);
}
