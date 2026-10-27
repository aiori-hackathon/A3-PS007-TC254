/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"SF Pro Text"',
          '"SF Pro Display"',
          '"SF Pro"',
          'system-ui',
          'sans-serif',
        ],
        display: [
          '"SF Pro Display"',
          '-apple-system',
          'BlinkMacSystemFont',
          '"SF Pro"',
          'system-ui',
          'sans-serif',
        ],
        body: [
          '"SF Pro Text"',
          '"SF Pro"',
          '-apple-system',
          'BlinkMacSystemFont',
          'system-ui',
          'sans-serif',
        ],
        mono: [
          '"SF Mono"',
          'SFMono-Regular',
          'ui-monospace',
          'Menlo',
          'Monaco',
          'Consolas',
          '"JetBrains Mono"',
          'monospace',
        ],
      },
      colors: {
        cyber: {
          900: '#070b14',
          800: '#0d1527',
          700: '#14203d',
          600: '#1e2f56',
          cyan: '#06b6d4',
          neon: '#10b981',
          crimson: '#ef4444',
          amber: '#f59e0b',
        }
      }
    },
  },
  plugins: [],
}
