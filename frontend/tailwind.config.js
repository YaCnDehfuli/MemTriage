/** Reads a CSS custom property (set per-theme in index.css) as an rgb()
 * color, so Tailwind's opacity modifiers (e.g. bg-accent/15) keep working
 * across both themes without any dark: variant classes in components. */
function themedColor(varName) {
  return ({ opacityValue }) =>
    opacityValue === undefined
      ? `rgb(var(${varName}))`
      : `rgb(var(${varName}) / ${opacityValue})`;
}

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Forensic + academic palette: warm bone ground in light mode, deep
        // slate in dark mode, restrained desaturated sage accent in both,
        // severity ramp reserved for risk only. Values live in index.css as
        // CSS custom properties so the whole palette can flip at once.
        // `surface` is background/border elevation (950 = canvas, 500 =
        // most prominent border); `ink` is text weight (400 = muted, 100 =
        // primary/darkest-or-lightest depending on theme).
        surface: {
          950: themedColor("--color-surface-950"),
          900: themedColor("--color-surface-900"),
          850: themedColor("--color-surface-850"),
          800: themedColor("--color-surface-800"),
          700: themedColor("--color-surface-700"),
          600: themedColor("--color-surface-600"),
          500: themedColor("--color-surface-500"),
        },
        ink: {
          400: themedColor("--color-ink-400"),
          300: themedColor("--color-ink-300"),
          200: themedColor("--color-ink-200"),
          100: themedColor("--color-ink-100"),
        },
        accent: {
          DEFAULT: themedColor("--color-accent"),
          soft: themedColor("--color-accent-soft"),
          dim: themedColor("--color-accent-dim"),
        },
        risk: {
          critical: themedColor("--color-risk-critical"),
          high: themedColor("--color-risk-high"),
          medium: themedColor("--color-risk-medium"),
          low: themedColor("--color-risk-low"),
          none: themedColor("--color-risk-none"),
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        panel: "var(--shadow-panel)",
      },
    },
  },
  plugins: [],
};
