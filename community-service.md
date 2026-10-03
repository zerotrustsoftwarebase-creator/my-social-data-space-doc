---
title: Communities — join one, or start your own
permalink: /community-service/
description: How to join a community in My (Social) Data Space with an invitation link or QR code, how to enter a service by hand, and how to start one yourself.
---

# Communities: join one, or start your own

**Last updated: 3 October 2026**

My (Social) Data Space keeps everything on your phone and works on its own.
Sharing with people nearby works out of the box, over an encrypted connection
between the two phones. Sharing with a *community* — people who are not in the
same room — goes through a **community service**: a small online database and
file store that the community runs, pays for and answers for itself.

**Nothing is built in.** The app comes with no community and no server of ours.
The service that receives what you publish is your choice, so you make it after
installing — usually by accepting an invitation. Until then the app says so on
the Feed, and what you share stays on your phone or goes to phones nearby.

> **In the closed test?** The test service's invitation and values are on the
> [closed-test page](../closed-test/). This page is the general explanation.

## Join with an invitation

The easiest way in. Whoever runs the community — or any member — sends you a
link or shows you a QR code.

1. Open the link on your Android phone, or scan the QR code with the camera.
   With the app installed, the link opens the app directly.
2. The app shows the service first: *Community invitation ready for review.*
   Check the address it names.
3. Tap **Use this service**. Nothing is connected before you do.
4. Choose your topics, then tap **Join selected topics and get posts**.

An invitation carries only the service's address and its public connection key.
It holds no password, no account and none of anybody's entries. If a link opens
in the browser instead of the app, the page shows the same three values to enter
by hand, as described next.

## Enter a service by hand

Three values, all of which the person running the service can give you:

| Field | What it looks like | Where it comes from |
|---|---|---|
| Service URL | `https://xxxxxxxx.supabase.co` | the project's API settings |
| Publishable key | `sb_publishable_…` | the same page — **never** a key starting with `sb_secret_` |
| Media bucket | `post_media` | preset; leave it empty unless the operator says otherwise |

1. Open **My data → Settings → Community service**.
2. Paste the URL and the publishable key. Leave the media bucket as it is.
3. Tap **Use this service**. The app checks that the service answers.
4. Optional: under **Save for later**, give the service a name and tap
   **Save to your services**. A saved service has a **Check** button, which
   asks the service what it will actually carry — which media types, how large a
   file, whether its schema is current — and keeps the answer with its date.

Connecting uploads nothing you already recorded. From then on, entries you mark
**Public** in one of its topics go there.

The app refuses a secret or service-role key by its shape. That is deliberate: a
secret key inside an app on somebody's phone is a secret no longer.

## Invite your members

While you use a service, **My data → Settings → Community service → Invite with
link or QR** shows a QR code and a **Copy invitation link** button. Send the link
or let people scan the code. Everyone still reviews the service and taps
**Use this service** themselves.

## Start a community — Supabase as the worked example

The service is ordinary Postgres behind PostgREST plus an object store. Any
Supabase project has exactly that, on the free tier, in about ten minutes.

1. **Create a project** at [supabase.com](https://supabase.com). Any region;
   the free tier is enough to start.
2. **Apply the schema.** Download
   [`apply_all_2026-10-03.sql`](../assets/community-service/apply_all_2026-10-03.sql),
   open the project's **SQL Editor**, paste the whole file in and press Run.
   It creates the tables, the policies and the `post_media` bucket in one go.
   Running it again later is safe — every statement only adds what is missing —
   and it is how you update a service set up from an older file.
3. **Copy the publishable key.** **Project Settings → API**: the value starting
   with `sb_publishable_`. Do not copy the secret key, and do not put it
   anywhere a phone could read it.
4. **Connect your own phone** with the URL and key as described above, then
   **invite your members**.

**Updating a service set up before October 2026.** The October schema makes
private-message and steward mailboxes readable only through a request for one
exact address, and caps how many drops an address takes per day. Run the latest
file again **after your members have updated the app**: versions of the app from
before October 2026 cannot collect private messages from a service that has it.
The current app works with the service either way.

## When it does not work

- **"Will not carry GIFs / this kind of file yet."** The service's schema is
  older than the app. Run the latest
  [schema file](../assets/community-service/apply_all_2026-10-03.sql) again;
  it only adds what is missing.
- **Private messages through the service never arrive.** The same cause: a
  service set up before September 2026 lacks the private-message mailbox. Run
  the latest schema file again.
- **Videos over a certain size wait for ever.** Supabase's free tier caps each
  file at **50 MB**, and that cap overrides a larger bucket setting. The app
  allows 100 MB, so a 60 MB video is refused and waits. Under 50 MB is fine.
- **Nothing arrives, no error.** A service running an old schema looks, to its
  members, exactly like one where nobody has posted. The **Check** button on a
  saved service tells the two apart: it asks the service what it will actually
  carry and names whatever is missing, with the fix. It writes nothing.

## What the service can and cannot see

Everything you publish into a community topic is readable by the service,
because carrying it is its job. Private messages are sealed to their recipient
before they leave your phone; the service carries them without being able to
read them. Your private entries, drafts and keys never reach it at all. The
[privacy policy](../privacy/) says the same thing at greater length.
