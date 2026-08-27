---
title: Closed test — connect the test service
permalink: /closed-test/
description: The two values closed-test testers paste into My (Social) Data Space to see the shared topics, and the exact taps to enter them.
---

## Closed test: connect the test community service

**For testers of the Google Play closed test, August–September 2026.**

The app ships with no community service built in, so right after installing,
Explore and the Feed are empty. For this test there is a **test server with
four topics and 22 example posts**. Connecting it takes one minute and two
pastes. Nothing else in the app needs it.

### 1. Copy the two values

<div class="copy-block">
  <label for="svc-url">Service URL</label>
  <div class="copy-row">
    <input id="svc-url" type="text" readonly value="https://ywbglcekixlmyhpsjghn.supabase.co">
    <button type="button" data-copy="svc-url">Copy</button>
  </div>
  <label for="svc-key">Publishable key</label>
  <div class="copy-row">
    <input id="svc-key" type="text" readonly value="sb_publishable_pacN3VPYl0LG4lkUqSEb7Q_yZXSx1tS">
    <button type="button" data-copy="svc-key">Copy</button>
  </div>
  <p class="copy-hint">Open this page on the phone that has the app, so you can paste directly. If a Copy button does nothing, long-press the value and copy it by hand.</p>
</div>

<style>
.copy-block{border:1px solid var(--line);border-radius:14px;padding:1rem 1.1rem;margin:1rem 0 1.5rem;background:var(--surface)}
.copy-block label{display:block;font-family:var(--font-head);font-weight:700;font-size:.85rem;letter-spacing:.06em;text-transform:uppercase;color:var(--ink);margin:.6rem 0 .35rem}
.copy-row{display:flex;gap:.5rem;align-items:stretch}
.copy-row input{flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.95rem;padding:.7rem .8rem;border-radius:10px;border:1px solid var(--line);background:var(--raised);color:var(--ink)}
.copy-row button{flex:none;min-width:5.5rem;padding:.7rem 1rem;border-radius:10px;border:0;background:var(--brand);color:var(--on-light);font-weight:700;font-size:1rem;cursor:pointer}
.copy-row button.done{background:var(--mint)}
.copy-hint{font-size:.92rem;color:var(--ink-2);margin:.9rem 0 0}
</style>
<script>
document.querySelectorAll('button[data-copy]').forEach(function(b){
  b.addEventListener('click',function(){
    var i=document.getElementById(b.getAttribute('data-copy'));
    i.select();i.setSelectionRange(0,99999);
    var ok=false;
    if(navigator.clipboard){navigator.clipboard.writeText(i.value).then(function(){b.textContent='Copied';b.classList.add('done');setTimeout(function(){b.textContent='Copy';b.classList.remove('done')},1800)});ok=true}
    if(!ok){try{document.execCommand('copy');b.textContent='Copied';b.classList.add('done');setTimeout(function(){b.textContent='Copy';b.classList.remove('done')},1800)}catch(e){}}
  });
});
</script>

### 2. Paste them into the app

1. Open the app. If you have not yet, tap **Create my private account** (it only creates a key on your phone — no sign-up).
2. Tap **My data** (bottom right) → **Settings** → **Community service**.
3. Paste the URL into **Service URL** and the key into **Publishable key**. Leave **Media bucket** as it is (`post_media`).
4. Tap **Use this service**. The app checks that the server answers.
5. Optional: tap **Save to your services** and give it a name, e.g. *Closed test*.

### 3. See it working

Tap **Explore**: you should see **Specialty Coffee**, **Powerlifting**, **Macro
Kitchen** and **Field Recordings**. Join the first three. The **Feed** now shows
the example posts — tap a post's photo (or the **Details** button) to flip it
to its data. From here, the tasks in the test description apply.

### What this service is

A community service is whoever receives what you publish. This one is a
temporary server run for this test by the app's developer; it will be deleted
after the test ends, together with everything posted to it. It sees what you
publish to a topic — never your private entries, drafts or keys, which stay on
your phone. The general explanation is on the
[Connect a community service](../community-service/) page.

Something not working? Write to **zerotrustsoftwarebase@gmail.com** with a
screenshot of what the app says.
