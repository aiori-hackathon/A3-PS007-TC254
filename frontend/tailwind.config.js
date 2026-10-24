/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
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
