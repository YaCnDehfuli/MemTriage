/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Forensic + academic dark palette: deep slate ground, restrained cyan
        // accent, severity ramp reserved for risk only.
        ink: {
          950: "#070b12",
          900: "#0b1017",
          850: "#0f151f",
          800: "#141c28",
          700: "#1c2735",
          600: "#293648",
          500: "#3b4a5e",
        },
        mist: {
          400: "#7688a0",
          300: "#9aabbf",
          200: "#c3cedd",
          100: "#e6ecf3",
        },
        accent: {
          DEFAULT: "#38c6d9",
          soft: "#1f6b76",
          dim: "#164e57",
        },
        risk: {
          critical: "#f0616d",
          high: "#f2994a",
          medium: "#e7c14b",
          low: "#5b8def",
          none: "#5b6b80",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
      },
    },
  },
  plugins: [],
};
