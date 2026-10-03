---
title: Privacy policy
permalink: /privacy/
---

## My (Social) Data Space privacy policy

**Last updated: 3 October 2026**

### 1. Who is responsible

The developer of My (Social) Data Space (GitHub: `zerotrustsoftwarebase-creator`) provides this app. For questions about this policy,
open **an issue at https://github.com/zerotrustsoftwarebase-creator/my-social-data-space-doc/issues** (please do not put personal data into a public issue).

### 2. The short version

This app keeps what you record on your own device. There is no account on our
servers, we operate no server that receives your data, and we do not collect
analytics or advertising identifiers. We cannot see your data, so we cannot sell
it, share it or hand it over. If you write to us for support, we receive only what
you choose to send.

Things leave your device only when you choose to share them, and then they go to
the people or the topic you picked — directly to a phone nearby, or through a
community service **you** connected. Until you connect one, the app talks to no
server at all.

### 3. What is stored, and where

**On your device only, always.** Your entries, drafts, private notes, your
cryptographic keys, your local reputation ledger, and the structure of the topics
you created. None of this is transmitted anywhere by the app on its own.

**Sent only when you act.** Each of the following leaves your device only as the
direct result of something you do:

| What | Leaves when |
|---|---|
| A post you publish — its values and caption | You publish it to a topic |
| Exact location | Only if you include it in a post you publish |
| Exercise and fitness detail | Only if you record it and publish it |
| Pictures and videos | Attached to a post you publish |
| Your profile name and picture | Carried with things you publish |
| Your identity key (a public identifier the app generates) | Signed onto everything you publish or send |
| Messages and reactions | You send them in a shared topic |
| A topic's structure and who may see it | You make that topic discoverable |
| A data request, or your answer to one | You create a request, or approve an answer |
| Challenge entries and governance votes | You create or cast them |
| An abuse report | You report something, and a community service is connected |
| Support details: app version, Android version and up to 20 fixed status codes | You review them in **Help**, then copy them or include them in an email you send |
| An invitation: a community service's address and public connection key | You share a link or QR code you created for it |

**Never sent.** Private entries, drafts, keys, and your local reputation ledger.
Private one-to-one messages travel sealed to the recipient's phone and never pass
through a community service.

### 4. Who receives it

**With no community service connected** (how the app is installed): only the
device you selected, directly over your local network. No operator, including us,
receives anything.

**Once you connect a community service:** whoever runs that service receives the
categories in §3 that you publish from then on, and keeps them so other people can
receive them. That operator is your choice, not ours — the app shows you the
address you are connecting to and tells you, before you save it, that what you
publish will go there under that operator's rules. We are not a party to that
relationship: we receive nothing from any service you connect, and we cannot see,
alter or delete what it holds. Read that operator's own policy before you publish.

Three specifics you should know before you publish anything:

- **Pictures and videos you publish are stored where anyone holding the link can
  fetch them.** They are addressed by their content, and location metadata is
  stripped before that address is computed, but the file itself is not access
  controlled.
- **Other people keep what you sent them.** Once somebody has received a post or a
  message, that copy is theirs and on their device.
- **A community service keeps what it was given.** The services this app speaks
  to are append-only: deleting a post publishes a signed deletion that every app
  honours, but the operator's copy is the operator's to remove.

**Support requests.** If you contact us from **Help**, your message goes from your
own email app to the support address shown there, and we receive what you write
and your email address. We use them only to answer you. Diagnostic details are
optional and never sent automatically. While the app runs it keeps at most 20 fixed
status codes, such as `SYNC_OFFLINE` or `SERVICE_UNREACHABLE`, from service setup,
sync and draft saving. They are held in memory only and forgotten when the app
closes. They contain no entries, messages, names, identifiers, service address or
key, times or device identifiers. **Review diagnostics** shows you the exact text,
together with the app version and Android version, before anything leaves your
phone. It leaves only if you then copy it, or choose **Include in email** and send
that email yourself. Cancelling sends nothing.

**Invitation links and QR codes.** Someone connected to a community service can
create a link or QR code for it. It carries only that service's address and its
public connection key, placed after the `#` in the link, a part browsers do not
send to any server. It carries no account key and no entries. With the app
installed, Android opens the link in the app, which shows the service for review;
nothing is connected until you press **Use this service**. Without the app, the
link opens a page on this website that shows the values for manual setup. That
page runs only in your browser, loads nothing from other sites and sends nothing
anywhere. Like every page of this website it is served by GitHub Pages, which, as
host, processes ordinary access data such as your IP address under GitHub's own
privacy statement.

### 5. Why

To make the app work: to deliver what you chose to share to the people you chose
to share it with, and to show you what other people published. There is no other
purpose. No profiling, no advertising, no analytics.

### 6. Permissions

The complete set the app declares — there is nothing else:

- **Notifications** — to tell you when an alert you configured has been met.
- **Biometric / fingerprint** — to unlock the app, if you turn that on. The check
  happens on your device and we never receive biometric data.
- **Internet and network state** — to reach a community service, if you connect
  one, and to find phones on your local network when you share nearby.
- **Run at start-up, vibrate, keep awake** — so a check you scheduled still runs
  after the phone restarts, and can tell you when it finds something.

**The app holds no camera permission and no photo-library permission**, and this is
worth stating precisely because it is easy to assume otherwise from what the app
can do. When you attach a picture or read numbers from a screenshot, the app asks
Android to open the system camera or the system picker; that system component hands
back the single file you chose, and the app never gains access to your camera or to
the rest of your library. Location metadata is stripped from an image before it is
addressed. Text recognition from a screenshot runs on your device.

The app requests no access to your contacts, your call log, your messages, your
precise location, or anything in the background beyond the scheduled check above.

A community service is only ever reached over an encrypted (`https`) connection;
the app refuses to save any other address. Nearby sharing between phones is
encrypted end to end on your local network.

### 7. Deleting your data

**On this device.** The app can erase everything it holds: every entry, every
message, your keys and your identity, behind a confirmation and a device unlock.
That is complete and immediate. You can also delete a single post you published:
this device stops offering it to phones nearby, and if a community service is
connected the app sends it a signed deletion, which every copy of this app that
receives it honours by hiding the post.

**Beyond this device.** We hold none of your data, so there is nothing for us to
delete. What we cannot reach, and what you should assume is permanent unless you
act on it:

- copies other people already received, and
- rows held by a community service you connected. The operator of that service —
  not us — decides what a deletion means there. Ask them directly; the address is
  the one you entered under **Settings → Community service**.

### 8. Children

This app is not directed to children. It carries content people write and lets
people message each other, and we do not knowingly collect anything from a child.

### 9. Changes

If this policy changes, the updated version appears at this address with a new
date. The app also shows a summary of this policy in **About**, and that summary is
updated with it.
