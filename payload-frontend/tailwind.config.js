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
          red: '#FF0000',
          dark: '#0A0A0A',
          gray: '#1A1A1A',
        }
      },
      fontFamily: {
        sans: ['Noto Sans', 'system-ui', 'sans-serif'],
        mono: ['Noto Sans Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
