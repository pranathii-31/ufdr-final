/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",  // All JS/JSX/TS/TSX files in src
    "./public/index.html"          // The index.html file
  ],
  theme: {
    extend: {
      colors: {
        primary: '#1a73e8',
        secondary: '#5f6368',
        background: '#f8f9fa'
      }
    }
  },
  plugins: []
}
