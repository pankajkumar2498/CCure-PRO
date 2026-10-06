/**
 * src/components/auth/AuthTrustFooter.jsx
 * Reusable Enterprise Security Trust Footer for Auth Components.
 */

export default function AuthTrustFooter() {
  return (
    <div className="auth-trust-footer">
      <span className="auth-trust-item">🔒 256-bit AES Encrypted</span>
      <span>•</span>
      <span className="auth-trust-item">SOC2 Compliant</span>
      <span>•</span>
      <span className="auth-trust-item">TLS 1.3 Secured 🛡️</span>
    </div>
  );
}
