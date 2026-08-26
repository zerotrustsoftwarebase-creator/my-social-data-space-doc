---
title: Connect a community service
permalink: /community-service/
---

## Connect a community service

> **Testing the closed test (August–September 2026)?** The test server's URL
> and key, with copy buttons and the exact taps, are on the
> [closed-test page](../closed-test/). This page is the general explanation.


**Last updated: 31 August 2026**

My (Social) Data Space keeps everything on your phone. Sharing with people
nearby works out of the box, over an encrypted connection between the two
phones. Sharing with a *community* — people who are not in the same room — goes
through a **community service**: a small database and file store that the
community runs for itself, pays for itself, and answers for itself.

**The app ships with no service built in.** That is deliberate. A service is
whoever receives everything you publish, so it is a choice you make after you
install, in **Settings → Community service**, not one made for you by whoever
built the app. Until you make it, the app says so on the Feed, and everything
you share stays on your device or goes to phones nearby.

### What you need

Three values, all of which the person running the service can give you:

| Field | What it looks like | Where it comes from |
|---|---|---|
| Service URL | `https://xxxxxxxx.supabase.co` | the project's API settings |
| Publishable key | `sb_publishable_…` | the same page — **never** a key starting with `sb_secret_` |
| Media bucket | `post_media` (leave as is) | preset; only change if the operator says so |

The app refuses a secret or service-role key by shape. That is not a bug: a
secret key inside an app on somebody's phone is a secret no longer.

### Enter it in the app

1. Open **My data → Settings → Community service**.
2. Paste the URL and the publishable key. Leave the bucket at `post_media`.
3. Press **Use this service**. The app checks whether the service answers.
4. Optionally press **Save to your services** and give it a name, then
   **Check** it. The check asks the service what it will actually carry — which
   media types, how large a file, whether its schema is current — and keeps the
   answer with the date it was taken.

Nothing you have already recorded is uploaded by this. From now on, what you
choose to publish into a community topic goes there.

### Run one yourself — Supabase as the worked example

The service is ordinary Postgres behind PostgREST plus an object store. Any
Supabase project has exactly that, on the free tier, in about ten minutes.

1. **Create a project** at [supabase.com](https://supabase.com). Any region;
   the free tier is enough to start.
2. **Apply the schema.** Download
   [`apply_all_2026-08-24.sql`](../assets/community-service/apply_all_2026-08-24.sql),
   open the project's **SQL Editor**, paste the whole file in and press Run.
   That is the only file to handle and the only time you handle it. It creates
   the tables, the policies and the `post_media` bucket in one go, and running
   it again later is safe — every statement only adds what is missing.
3. **Copy the publishable key.** **Project Settings → API**: the value starting
   with `sb_publishable_`. Do not copy the secret key; do not put it anywhere a
   phone could read it.
4. **Hand out the URL and the key** to the people in your community. They enter
   both as described above.

### When it does not work

- **"Will not carry GIFs / this kind of file yet."** The service's schema is
  older than the app. Re-run the latest
  [schema file](../assets/community-service/apply_all_2026-08-24.sql); it only
  adds what is missing.
- **Videos over a certain size wait for ever.** Supabase's free tier caps each
  file at **50 MB**, and that cap overrides a larger bucket setting. The app
  allows 100 MB, so a 60 MB video is refused and waits. Under 50 MB is fine.
- **Nothing arrives, no error.** A service running an old schema is
  indistinguishable, to its members, from one where nobody has posted. The
  app's **Check** on the Community service screen tells the two apart: it asks
  the service what it will actually carry and names whatever is missing, with
  the fix. It writes nothing to the service.

### What the service can and cannot see

Everything you publish into a community topic is readable by the service,
because carrying it is its job. Direct messages are sealed to the recipient
before they leave your phone; the service carries them without being able to
read them. Your private entries, drafts and keys never reach it at all. The
[privacy policy](../privacy/) says the same thing at greater length.

Moving a topic from one service to another — and letting a community vote on
that — is on the way, and is deliberately not a checkbox: it is a protocol
decision about who receives what you publish from now on, and it is written
down before it is built.
