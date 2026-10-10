# linkedin-feed-reader

Exports the posts and activity of **your own** LinkedIn profile to JSON or CSV.

It uses LinkedIn's official **Member Data Portability API** (self-serve, available to
members in the EU/EEA/Switzerland) rather than scraping with your password. Scraping breaks
LinkedIn's terms of service and tends to run into CAPTCHAs or get the account restricted.

## Setup

1. Go to <https://www.linkedin.com/developers/apps> and create a **new** app. When it asks
   for a **LinkedIn Page**, pick LinkedIn's default page for this API:
   [Member Data Portability (Member) Default Company](https://www.linkedin.com/company/member-data-portability-member-default-company/).

   > **Don't create your own company page.** LinkedIn only grants access to the Member Data
   > Portability API for apps linked to this default page. With any other page, the product
   > can't be requested.
2. Under **Products**, request **Member Data Portability API (Member)**. Approval is instant.
   This product must be the only one on the app.
3. Under **Auth → Authorized redirect URLs**, add `http://localhost:8765/callback`.
4. Copy the Client ID and Client Secret.

```bash
py -3.14 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## Usage

```bash
python linkedin_feed.py configure                 # profile, client id/secret -> encrypted vault
python linkedin_feed.py login                     # browser consent, token stored in vault
python linkedin_feed.py export -f csv             # your posts -> export/*.csv
python linkedin_feed.py export -d MEMBER_SHARE_INFO ALL_COMMENTS ARTICLES
python linkedin_feed.py interactions -f csv       # network posts you liked/commented on
python linkedin_feed.py interactions --since 2026-01-01
python linkedin_feed.py changelog -f csv          # activity since consent, last 28 days
python linkedin_feed.py show                      # redacted vault contents
```

### Snapshot vs. changelog

LinkedIn gives you two separate data sources:

| | `export` / `interactions` (Snapshot API) | `changelog` (Changelog API) |
|---|---|---|
| Content | Your history up to the moment you gave consent | Your activity *after* you gave consent |
| Time span | Everything | Last 28 days |
| When ready | Some domains take hours to days | Within seconds |

A post you write after `login` is therefore only in `changelog`, not in `export`. If
`export` returns nothing for a domain, LinkedIn has probably not finished building that part
of the snapshot yet. Try again later.

`changelog` makes sure LinkedIn is recording your activity, and turns it on if not. As CSV it
writes one row per event: time, method, resource, post URL, reaction type and text. As JSON it
writes the full raw events. `--resource` keeps only some kinds of events, for example
`--resource ugcPosts`.

`interactions` combines `ALL_LIKES` and `ALL_COMMENTS` into one row per post. Each row has the
post URL and URN, the first and last time you interacted with it, how many reactions you left
and of which types, and your comments. Rows are newest first. Comment links are matched to
their parent post, so liking and commenting on the same post gives one row. The export does
**not** include the text of the post itself, because LinkedIn's API only returns your own
activity.

Useful domains: `MEMBER_SHARE_INFO` (your posts), `ARTICLES`, `ALL_COMMENTS`, `ALL_LIKES`,
`PROFILE`.

## Security

- Everything is stored in `~/.linkedin_feed_reader/vault.json`: profile, client ID/secret
  and OAuth tokens. The file is encrypted with **AES-256-GCM**, and the key is derived from
  your passphrase with **scrypt**. Use `--vault` to put it somewhere else.
- For unattended runs you can set the passphrase in the `LFR_PASSPHRASE` environment
  variable. Doing so puts the passphrase in your environment.
- Access tokens last about 60 days. When one expires, run `login` again. If LinkedIn issued
  a refresh token, the script refreshes automatically instead.

## Limitations

- This exports **your own** content only. LinkedIn has no API for reading your home feed,
  meaning other people's posts.
- According to LinkedIn's docs, the snapshot and changelog endpoints only accept
  `LinkedIn-Version: 202312`, so that's the default. If LinkedIn rejects it (HTTP 426
  `NONEXISTENT_VERSION`), the script tries the version saved in the vault, then each month
  from the current one backwards. LinkedIn writes `202312` as `20231201` in its error
  messages. To force a version, use `--api-version`.
