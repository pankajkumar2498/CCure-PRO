import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { AuthProvider } from "@shell/auth/AuthContext";
import { PreferencesProvider } from "@audit/context/PreferencesContext";
import RootErrorBoundary from "@audit/components/common/RootErrorBoundary";

// ── Stylesheet order is load-bearing ─────────────────────────────────────────
// The design system (UX4G tokens + CCure semantics + CCure components) must be
// parsed BEFORE the legacy stylesheets.
//
// UX4G wraps its reset in `:where(…)`, which has zero specificity, so every
// CCure rule already outranks it. But two zero-specificity rules — UX4G's
// `:where(*,:before,:after)` and CCure's own `*` reset in theme.css — are
// decided by source order alone. With the design system first, CCure's reset
// wins the tie and unmigrated pages render exactly as they did.
//
// Reversing these two lines is not a formatting change; it silently hands the
// reset to UX4G.
import "./design-system";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <PreferencesProvider>
          <RootErrorBoundary>
            <App />
          </RootErrorBoundary>
        </PreferencesProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
