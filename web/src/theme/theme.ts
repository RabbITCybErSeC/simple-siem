export type ThemePreference = "system" | "light" | "dark";

const STORAGE_KEY = "simple-siem.theme";
const DARK_MEDIA_QUERY = "(prefers-color-scheme: dark)";

export function readThemePreference(): ThemePreference {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isThemePreference(stored) ? stored : "system";
  } catch {
    return "system";
  }
}

export function writeThemePreference(preference: ThemePreference): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, preference);
  } catch {
    // Storage can be unavailable; the theme still applies for this page.
  }
}

export function applyTheme(preference: ThemePreference): () => void {
  if (preference !== "system") {
    document.documentElement.classList.toggle("dark", preference === "dark");
    return () => {};
  }

  const mediaQuery = window.matchMedia(DARK_MEDIA_QUERY);
  const applySystemTheme = () => {
    document.documentElement.classList.toggle("dark", mediaQuery.matches);
  };

  applySystemTheme();
  mediaQuery.addEventListener("change", applySystemTheme);

  return () => mediaQuery.removeEventListener("change", applySystemTheme);
}

function isThemePreference(value: string | null): value is ThemePreference {
  return value === "system" || value === "light" || value === "dark";
}
