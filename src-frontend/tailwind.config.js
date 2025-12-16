/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {},
  },
  plugins: [
    require('@catppuccin/tailwindcss')({
      // prefix to use, e.g. 'ctp' -> 'ctp-pink'
      // default is 'false' (no prefix)
      prefix: false,
      // which flavour of colours to use
      // default is 'mocha'
      defaultFlavour: 'mocha',
    }),
  ],
}