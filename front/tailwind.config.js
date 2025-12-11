/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'dark-bg': '#111827',
        'dark-card': '#1F2937',
        'danger': '#EF4444',
        'caution': '#F59E0B',
        'safe': '#10B981',
        'accent': '#06B6D4',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
