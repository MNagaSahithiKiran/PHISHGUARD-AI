/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,html}",
    "./popup.html",
    "./options.html"
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#070b14',
          900: '#0b1120',
          800: '#131e36',
          700: '#1e2e4f',
          border: '#1f2e4d',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
