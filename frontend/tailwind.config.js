export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primaryBg: "#FF1D8D", // Light mode background
        hoverBg: '#0080000',
        darkBg: "#1a202c", // Dark mode background
      },
    },
  },
  plugins: [],
};
