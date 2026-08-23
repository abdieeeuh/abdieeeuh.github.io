---
title: "Alias to Scene"
ctf: "$N1PH€RS 3.0 CTF"
date: 2026-08-23
category: osint
flag_format: "$N1PH€RSxTCTF{BIKE_COLOR_HELMET_BRAND}"
---

# Alias to Scene

## Summary

The supplied alias `lospolloshermanos165` led to a public GitHub account. A deleted-file breadcrumb in the repository history exposed a Gmail address, whose public calendar contained the exact scene reference. The scene footage then supplied the two requested visual fields: a black bike and an `EXORCIST` helmet.

## Solution

### Step 1: Trace the alias to GitHub history

The exact username has a [public GitHub account](https://github.com/lospolloshermanos165) and a repository named `Gustavo-Gus-Fring-`. The current repository contents are not enough, so inspect its commit history. Commit `41763a8a4bae26f96fb3aef3ce5933207f3dc75a` added a file named `you can call me GUS`:

```bash
alias='lospolloshermanos165'
repo='Gustavo-Gus-Fring-'
commit='41763a8a4bae26f96fb3aef3ce5933207f3dc75a'

curl -fsSL \
  "https://api.github.com/repos/$alias/$repo/commits/$commit" |
  jq '{sha,html_url,message:.commit.message,
       files:[.files[] | {filename,status,patch}]}'
```

Relevant output:

```text
sha: 41763a8a4bae26f96fb3aef3ce5933207f3dc75a
message: Create you can call me GUS
filename: you can call me GUS
status: added
patch: +heisenbergthecook436@gmail.com
```

The historical commit is publicly available at:

`https://github.com/lospolloshermanos165/Gustavo-Gus-Fring-/commit/41763a8a4bae26f96fb3aef3ce5933207f3dc75a`

The file was subsequently removed in commit `e037bcd3bdbfece7d44e31066e5e56fab9e1df22`, so looking only at the current repository would miss the breadcrumb:

`https://github.com/lospolloshermanos165/Gustavo-Gus-Fring-/commit/e037bcd3bdbfece7d44e31066e5e56fab9e1df22`

### Step 2: Use the exposed email to find the scene reference

The address has a public Google Calendar feed. Fetching the feed gives one event with a deliberate title:

```bash
curl -fsSL \
  'https://calendar.google.com/calendar/ical/heisenbergthecook436%40gmail.com/public/basic.ics' |
  rg 'SUMMARY|DTSTART|DTEND'
```

Output:

```text
DTSTART:20260228T060000Z
DTEND:20260228T070000Z
SUMMARY:MANKATHA Bike chasing Scene was Damnnnnn
```

This identifies the intended scene as the motorcycle chase from *Mankatha*. The public calendar feed is:

`https://calendar.google.com/calendar/ical/heisenbergthecook436%40gmail.com/public/basic.ics`

### Step 3: Inspect the referenced scene

The matching public clip is the Sun NXT scene:

`https://www.youtube.com/watch?v=Ixvgc7l0KyU`

Inspecting the chase footage gives:

- Bike color: **BLACK**
- Helmet marking/brand requested by the challenge: **EXORCIST**

The clip thumbnail also shows the black motorcycle:

`https://i.ytimg.com/vi/Ixvgc7l0KyU/maxresdefault.jpg`

The helmet marking is clearly visible in this frame:

`https://pbs.twimg.com/media/GW5GsaOW4AED9MU?format=jpg&name=orig`

For reproducibility, the downloaded JPEG was 1470×816 pixels with SHA-256:

```text
d787fd9da9c1baf9f1d17c07b29c7e704ec60af75af0c5f68d70e38bdce5aafa
```

## Flag

```text
$N1PH€RSxTCTF{BLACK_EXORCIST}
```