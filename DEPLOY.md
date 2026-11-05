# ASCTEMUN Cloud Deployment

This package turns the existing ASCTEMUN Conference Management HTML app into a static website with:

- email/password sign-in through Supabase Auth
- a **My Committees** dashboard
- separate saved committee records per account
- cloud persistence of the app's existing committee state
- archive / unarchive / delete committee controls
- a browser-session fallback while the cloud is unavailable

## 1. Create the database

Create a Supabase project, open its SQL Editor, and run `supabase_schema.sql`.

The table is protected with Postgres Row Level Security so a signed-in user can only read/write their own committee rows.

## 2. Configure the website

Open `index.html` and find:

```js
const SUPABASE_CONFIG = {
  url: "https://YOUR-PROJECT.supabase.co",
  key: "YOUR_SUPABASE_PUBLISHABLE_OR_ANON_KEY"
};
```

Replace those two placeholders with the project's URL and browser-safe publishable/anon key.

Do **not** put a Supabase secret/service-role key in this file.

## 3. Deploy

This is a static HTML site, so you can deploy the folder to a static host such as Vercel, Netlify, GitHub Pages, Cloudflare Pages, or any ordinary web server.

Use `index.html` as the site entry point.

## 4. Auth settings

In Supabase Auth, configure your desired email confirmation behavior and add your deployed site's URL to the allowed redirect/site URL settings.

## 5. First use

1. Open the deployed site.
2. Create an account or sign in.
3. Create a committee.
4. Use the existing MUN management interface normally.
5. Changes are automatically synced to the selected committee.
6. Return to **My Committees** to open a past committee.

## Important design note

The current app stores its working state as one JSON object containing delegates, motions, resolutions, notes, speaker state, and related committee data. This version preserves that structure rather than rewriting the entire application into a framework.

For a larger production system, the next step would be normalizing delegates, motions, resolutions, attendance, and notes into separate database tables and adding committee membership/roles.
