import type { Config } from "tailwindcss";

const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: token("bg"),
        surface: token("surface"),
        raised: token("raised"),
        border: token("border"),
        fg: token("fg"),
        muted: token("muted"),
        subtle: token("subtle"),
        accent: token("accent"),
        cyan: token("cyan"),
        good: token("good"),
        warn: token("warn"),
        bad: token("bad"),
        info: token("info"),
        // fixed ink chrome (sidebar / topbar / home)
        chrome: {
          bg: token("chrome-bg"),
          surface: token("chrome-surface"),
          raised: token("chrome-raised"),
          fg: token("chrome-fg"),
          muted: token("chrome-muted"),
          subtle: token("chrome-subtle"),
          border: token("chrome-border"),
          accent: token("chrome-accent"),
        },
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Cascadia Mono", "Consolas", "monospace"],
      },
      borderRadius: { lg: "10px", md: "8px", sm: "6px" },
      boxShadow: {
        card: "0 1px 2px rgb(0 0 0 / 0.05), 0 2px 8px rgb(0 0 0 / 0.04)",
        pop: "0 12px 32px rgb(0 0 0 / 0.18)",
        chrome: "0 8px 30px rgb(0 0 0 / 0.5)",
      },
      keyframes: {
        pulseDot: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.35" } },
        shimmer: { "100%": { transform: "translateX(100%)" } },
        glowPulse: {
          "0%,100%": { boxShadow: "0 0 0 0 rgb(var(--chrome-accent) / 0.0)" },
          "50%": { boxShadow: "0 0 16px -2px rgb(var(--chrome-accent) / 0.6)" },
        },
        riseIn: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        pulseDot: "pulseDot 1.6s ease-in-out infinite",
        shimmer: "shimmer 1.4s infinite",
        glowPulse: "glowPulse 2.8s ease-in-out infinite",
        riseIn: "riseIn 0.5s ease-out both",
      },
    },
  },
  plugins: [],
} satisfies Config;
