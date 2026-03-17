# Abdi Writeups

Personal CTF and web exploitation blog based on
[astro-erudite](https://github.com/jktrn/astro-erudite) by
[enscribe](https://enscribe.dev).

Built with:

- Astro
- Tailwind CSS
- shadcn/ui
- MDX

## Development

```bash
npm install
npm run dev
```

The local development server runs on `http://localhost:1234`.

## Content Layout

- Posts: `src/content/blog/`
- Authors: `src/content/authors/`
- Categories page: `src/pages/categories/`
- Site metadata and navigation: `src/consts.ts`

## Before Deploying

- Replace `https://example.com` in `astro.config.ts` and `src/consts.ts`
- Update the content in `src/content/blog/` with your real writeups
- Replace the favicon and avatar assets in `public/` if you want your final branding
