/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber-blue': '#00D4FF',
        'cyber-purple': '#8B5CF6',
        'dark-bg': '#0F172A',
        'card-bg': '#1E293B',
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
