# Swiper Security Report — 2026-11-24

## Changes applied to the live Supabase project

- Confirmed RLS is enabled on every public table: 0 public tables without RLS.
- Confirmed no public SECURITY DEFINER function is executable by `anon`.
- Confirmed every public SECURITY DEFINER function has a fixed `search_path`.
- Added private username-login audit storage. It stores HMAC hashes of account/IP identifiers, outcome codes, and timestamps; it does not store raw passwords, usernames, or IP addresses.
- Deployed username login Edge Function version 6 with IP, per-account/IP, and global per-account 15-minute rate limits and audit events.
- Added global-chat read protection so anonymous guest sessions cannot read messages; registered accounts can read.
- Hardened chat membership RPCs so anonymous guest sessions cannot be treated as chat members.
- Hardened moderator update-log policies against anonymous sessions.
- Hardened radio Edge Functions to use the trusted `cf-connecting-ip` header for rate-limit identity instead of client-supplied `x-forwarded-for` / `x-real-ip` fallbacks.
- Deployed radio functions: register-track v2, skip-vote v5, advance v2.
- Changed default privileges for future objects created by `postgres` in `public`: no automatic table/sequence access for `anon` or `authenticated`, and no automatic function execution for `PUBLIC`, `anon`, or `authenticated`. New migrations must explicitly grant the minimum required access.

## Admin and moderation boundaries checked

- Moderator badge table: clients can read badges, but neither anonymous nor authenticated clients can insert moderator badges.
- Shop catalog: client writes are revoked.
- Admin announcements: writes remain protected by the admin email/non-anonymous policy.
- Title definitions and user title awards: writes remain protected by admin policies.
- Admin moderation and verification RPCs require the designated non-anonymous admin identity.
- Moderator review RPCs require a moderator badge and reject anonymous sessions.

## GitHub source and migration

- `supabase/migrations/20261124000100_swiper_auth_hardening.sql` records the database changes, including the private login audit table/function.
- `supabase/functions/swiper-username-login/index.ts` contains the deployed username login handler.
- Radio Edge Function sources are stored under `supabase/functions/`.

## Remaining advisor notices and intentional exceptions

- Supabase still reports authenticated-callable SECURITY DEFINER functions. These are required application RPCs for matchmaking, chat, shop, radio, and account features. The audit confirmed 0 are callable by `anon`, all have fixed search paths, and the inspected user-facing functions contain account, membership, moderator, or admin checks. Do not blanket-revoke them: that would break application features.
- Anonymous sign-ins remain enabled because Swiper supports Guest Quick Play. Guest sessions are blocked from profile, friend, private chat, and global chat operations where registered-account access is required.
- Leaked Password Protection remains disabled because the project plan does not expose that setting. The signup UI now requires at least 8 characters; this does not replace compromised-password screening.
- GitHub code searches for common Supabase secret-key patterns returned no matches. This is a targeted code search, not a guarantee that every possible secret format has been scanned.

## Operational notes

- Do not put the service-role key in GitHub or frontend code.
- Keep new SQL migrations explicit about RLS and minimum grants.
- Re-run Supabase Security Advisor after future schema/function changes.


## Final Security Advisor review

The latest Security Advisor still reports 53 authenticated-callable SECURITY DEFINER RPCs, 9 anonymous-policy notices, and the plan-gated leaked-password warning.

The remaining anonymous-policy notices were reviewed individually:
- `swipe_room_players` and `swipe_rooms`: guest matchmaking requires room access.
- `swipe_reports` and `swiper_shop_inventory`: policies are scoped to the caller's own user ID.
- `swipe_titles`, `swipe_tournaments`, and `swiper_update_logs`: intentionally public display data.
- `cron.job` and `cron.job_run_details`: extension policies are flagged by the advisor, but the `cron` schema is not usable by `anon` or `authenticated`; extension internals were left untouched.

The global chat anonymous read policy was removed. The replacement requires a registered, non-anonymous session. The two chat-membership RPCs also explicitly reject anonymous sessions.

The 53 SECURITY DEFINER notices are not blindly suppressed. They are app RPCs that need elevated access to implement existing RLS-protected workflows. Anonymous execution is 0, every function has a fixed search path, and the admin/moderator endpoints retain explicit identity or badge checks.

Final database verification:
- Public tables without RLS: 0
- Public SECURITY DEFINER functions executable by `anon`: 0
- Public SECURITY DEFINER functions without a fixed search path: 0
- Anonymous chat-read policies: 0
- Client ability to grant moderator badges: blocked
- Client ability to edit the shop catalog: blocked
- Automatic client grants on future public tables, sequences, and functions: revoked
