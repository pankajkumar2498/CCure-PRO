import { CcureIcon, CcureIconButton } from "../../design-system";
import { usePreferences } from "../preferences/PreferencesContext";
import { ToastContainer, useToasts } from "../feedback/Toast";

export default function ThemeToggle() {
  const { theme, loading, savingTheme, toggleTheme } = usePreferences();
  const { toasts, push, dismiss } = useToasts();
  const label =
    theme === "dark" ? "Switch to light mode" : "Switch to dark mode";

  const handleClick = async () => {
    try {
      await toggleTheme();
    } catch {
      push("Could not save the theme preference. Please try again.", "error");
    }
  };

  return (
    <>
      <CcureIconButton
        size="sm"
        className="sh-iconbtn"
        aria-label={label}
        title={label}
        aria-busy={savingTheme || undefined}
        disabled={loading || savingTheme}
        onClick={handleClick}
      >
        <CcureIcon name={theme === "dark" ? "sun" : "moon"} size={16} />
      </CcureIconButton>
      <ToastContainer toasts={toasts} dismiss={dismiss} />
    </>
  );
}
