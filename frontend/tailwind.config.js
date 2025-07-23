module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      colors: {
        'cyber-blue': '#00D4FF',
        'cyber-purple': '#8B5CF6',
        'cyber-green': '#10B981',
        'cyber-red': '#EF4444',
        'cyber-yellow': '#F59E0B',
        'dark-bg': '#0F172A',
        'card-bg': '#1E293B',
        'surface': '#334155',
        'border': '#475569'
      },
      fontFamily: {
        'inter': ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'bounce-slow': 'bounce 2s infinite',
        'spin-slow': 'spin 3s linear infinite',
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0, 212, 255, 0.3)',
        'threat': '0 0 20px rgba(239, 68, 68, 0.3)',
        'safe': '0 0 20px rgba(16, 185, 129, 0.3)',
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
