---
title: Connect a tool or machine
permalink: /connected-tools/
description: Download one file, make a topic, approve what it may do. No toolchain, no source code, nothing to build.
---

# Connect a tool or machine

**Last updated: 31 August 2026**

A connected tool adds readings from a camera system, sensor hub, server or
script to a topic on your phone. It runs separately, has its own key, and can
use only the topic, fields, rate and end date you approve.

Setting one up is four steps and one download. There is nothing to build and
no source code to fetch.

<dl class="layer-list">
  <div>
    <dt>On your computer <span>The connector</span></dt>
    <dd><strong>What it is</strong>One Python file that reads your machine and speaks to your phone.</dd>
    <dd><strong>What it needs</strong>Python 3 and one package. No app source, no Flutter, no build.</dd>
  </div>
  <div>
    <dt>Between the two <span>A private connection</span></dt>
    <dd><strong>What it is</strong>An invite you copy on the phone and paste into the connector, once.</dd>
    <dd><strong>What it needs</strong>Both devices on the same private network. Nothing goes outward.</dd>
  </div>
  <div>
    <dt>On your phone <span>The permission</span></dt>
    <dd><strong>What it is</strong>The topic, fields, rate and end date you pick when you review it.</dd>
    <dd><strong>What it needs</strong>Your approval. The connector cannot widen it later.</dd>
  </div>
</dl>

### What you need

- A computer that can reach both the machine and the phone on the same private
  network — a laptop, a home server, a Raspberry Pi. The connector does not
  run inside the phone app.
- **Python 3.9 or newer.** macOS and Linux already have it; on Windows install
  it from [python.org](https://www.python.org/downloads/).
- The machine's address and, if it asks for one, a sign-in.

### 1. Get the connector

[**Download `mds-connector.zip`**](../assets/connector/mds-connector.zip)
— or read
[`mds_connector.py`](../assets/connector/mds_connector.py)
first, which is the whole program.

Unzip it, then in that folder:

```sh
python3 -m pip install --user cryptography
python3 mds_connector.py check
```

`check` proves the connector's encryption against its published test vectors
and confirms every refusal it relies on. It should print that everything
checks out. If it prints anything else, stop there.

### 2. Make the topic

```sh
python3 mds_connector.py profiles
python3 mds_connector.py fields --profile frigate
```

`profiles` lists the machines the connector already knows — Frigate over HTTP
or MQTT, Home Assistant sensors, Zigbee2MQTT, Plex, Streamystats, GitLab and
Ollama. `fields` prints the topic to create in the app, under
**My data → Topics → New topic**. Neither reads your machine and neither
writes anything.

### 3. See what it would add

Put the machine's address and sign-in in a file only you can read,
`~/.mds-connector/credentials`:

```
link: https://camera-system.local
user: bridge-reader
password: replace-this
```

Then:

```sh
python3 mds_connector.py preview --profile frigate
```

This signs in to the machine and prints the exact entries it would add. It
does not contact your phone and writes nothing anywhere. **This is the step
worth spending time on**: if the values or units look wrong, fix them here.

### 4. Connect it

In the app open **My data → Connected tools → Create private invite**, choose
your phone's private network, and copy the invite. Keep that screen open, then:

```sh
python3 mds_connector.py connect --profile frigate \
    --topic '<topic id>' --invite '<paste the whole invite>' --every 30
```

Your phone shows the tool's name and what it is asking for. Check the name,
pick only the topic and fields it needs, set a sensible rate and an end date,
and approve. From then on it carries readings every thirty seconds.

To start it again later — after a reboot, or when you stopped it:

```sh
python3 mds_connector.py run --profile frigate --topic '<topic id>' --every 30
```

It remembers your phone's address, so there is nothing to type again. The app
must be open while readings are being carried. Pause or disconnect the tool at
any time from **My data → Connected tools**.

### Keep the connector's own file

The connector keeps its key and its progress in
`~/.mds-connector/<topic>.json`. **Treat that file as a secret and back it
up.** The permission on your phone was issued to the key inside it, so losing
it means connecting again and approving again.

### Adding another machine

Each machine the connector knows is one small JSON file in `profiles/`. Copy
the closest one and change only its address, sign-in, which records to read,
and how a record becomes an entry. Then run `fields` and `preview` again
before you connect anything.

The mapping vocabulary is deliberately small — read some text, read a number,
measure a duration, join a list, count things, use a fixed value. If a machine
needs a rule the connector does not know, it is not safe to hide that
behaviour in a settings file.

### When it does not work

- **"That is not a usable invite."** Copy a fresh one, including the whole
  `mds-tool-invite.v1.` beginning. Invites are short-lived and only one
  connection at a time is allowed.
- **It cannot reach the phone.** Keep the app open and put both devices on the
  same private Wi-Fi or wired network. Guest Wi-Fi usually blocks devices from
  reaching each other.
- **`preview` reads nothing.** Check the machine's address and sign-in before
  involving the phone at all. Nothing about your phone can cause this.
- **Every reading is refused as out of scope.** The topic or fields do not
  match what you approved. Disconnect the tool on the phone and connect it
  again with exactly the right topic.
- **It says it is not connected any more.** Restore its
  `~/.mds-connector/` file from a backup. Deleting that file creates a new
  identity, which needs a fresh invite and a fresh approval.
- **`pip` is not found on Windows.** Use `py -m pip install cryptography` and
  `py mds_connector.py` instead of `python3`.

The connector carries only what its profile maps and what you permitted. It
never turns the machine itself into something your phone trusts, and it never
makes a machine's cloud account part of your account.
