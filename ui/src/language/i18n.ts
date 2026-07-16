import { init, register, locale, getLocaleFromNavigator } from "svelte-i18n";

// Auto-collect every namespace file for every locale. Adding a new
// src/language/<locale>/<namespace>.json requires no changes here — Vite
// statically analyses this glob at build time.
const modules = import.meta.glob("./{en,zh}/*.json");

export const SUPPORTED_LOCALES = [
  { code: "en", label: "English" },
  { code: "zh", label: "中文" },
];

const STORAGE_KEY = "gs_locale";

function detectInitialLocale(): string {
  const saved =
    typeof localStorage !== "undefined" ? localStorage.getItem(STORAGE_KEY) : null;
  if (saved && SUPPORTED_LOCALES.some((l) => l.code === saved)) {
    return saved;
  }
  const nav = getLocaleFromNavigator();
  if (nav && nav.toLowerCase().startsWith("zh")) {
    return "zh";
  }
  return "en";
}

export const setupI18n = () => {
  for (const path in modules) {
    const match = path.match(/\.\/(\w+)\//);
    if (!match) continue;
    const loc = match[1];
    // svelte-i18n merges (addMessages) all loaders registered for the same
    // locale, so splitting messages across namespace files is supported.
    register(loc, async () => (await (modules[path]() as Promise<any>)).default);
  }

  init({
    fallbackLocale: "en",
    initialLocale: detectInitialLocale(),
  });
};

export const setLocale = (code: string) => {
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(STORAGE_KEY, code);
  }
  locale.set(code);
};
