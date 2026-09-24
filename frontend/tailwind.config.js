/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#070b14',
          900: '#0c1222',
          850: '#11192e',
          800: '#17233f',
          700: '#1e3056',
          border: '#1f2e4d',
          cyan: '#06b6d4',
          cyanGlow: 'rgba(6, 182, 212, 0.25)',
          blue: '#3b82f6',
          emerald: '#10b981',
          rose: '#f43f5e',
          amber: '#f59e0b'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
