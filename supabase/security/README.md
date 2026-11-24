# Swiper security audit — 2026-11-24

Supabase project: `upghyzhawctughyojwpo`  
Repository: `playswiper/Swiper`

## Applied and verified

### Database access

- RLS is enabled on every table in the exposed `public` schema.
- No `anon` or `authenticated` table privileges remain for `TRUNCATE`, `REFERENCES`, or `TRIGGER` on public tables.
- No public-schema `SECURITY DEFINER` function is executable by the `anon` role.
- Sensitive profile columns (moderation details, block lists, login-message state, and reward-unlock flags) are no longer selectable directly by signed-in clients. Public profile fields remain selectable.
- Private profile state, including chat-rules acceptance, is returned through the caller-scoped `swipe_my_profile_private_state()` RPC.
- Admin moderation, admin search, and verification RPCs require the non-anonymous admin identity `mystarsnight@gmail.com`.
- Client roles cannot add, edit, or delete moderator badges or shop-catalog rows.
- The public outage-status endpoint is now a SECURITY INVOKER wrapper around an aggregate-only implementation in the non-exposed `private` schema.
- The shop crate wrapper is SECURITY INVOKER; the underlying pack-opening function performs the account and ownership checks.

### Radio abuse prevention

Browser clients are now read-only for radio database mutations. Direct client inserts to the queue and skip-vote tables are revoked; direct station and track mutations are also revoked. Radio mutations use server-side Edge Functions and service-role-only RPCs.

| Edge Function | Live version | Controls |
|---|---:|---|
| `swiper-username-login` | 6 | CAPTCHA, origin/API-key validation, IP and account throttles, hashed login audit |
| `swiper-radio-register-track` | 1 | Audius metadata fetched server-side, 80 requests/IP/15 minutes, service-only track writes |
| `swiper-radio-skip-vote` | 2 | 12 requests/IP/10 minutes, per-track HMAC voter IDs, service-only vote writes |
| `swiper-radio-advance` | 1 | 30 requests/IP/15 minutes; database verifies the expected current track and duration |

The radio queue's paid request flow remains the `radio_request_track()` RPC, which checks the registered account and charges 750 coins. The client can no longer bypass it with a direct queue insert.

All four Edge Functions are ACTIVE. Their gateway `verify_jwt=false` setting is intentional: these endpoints support login and guest radio use, and each handler validates the public API key, allowed browser origin, request shape, and server-side limits. Service-role credentials remain server-side.

### Login audit

- Private table: `private.swiper_auth_login_audit`
- RLS enabled; only service-role audit writes are allowed.
- Account and IP identifiers are HMAC hashes, not raw usernames, emails, or IP addresses.
- Event types: success, invalid credentials, unknown account, and rate limited.
- Old records are opportunistically cleaned after 30 days.
- The audit table currently contains zero events; the new handler has not yet recorded a real login attempt during this audit.

### GitHub changes

- Signup minimum raised from 6 to 8 characters.
- Chat-rules acceptance reads through the private-state RPC.
- Radio registration, skip voting, and station advancement use the new Edge Functions.
- Security SQL is documented in [2026-11-24-hardening.sql](./2026-11-24-hardening.sql).

## Latest Supabase Advisor report

### Security

- 0 public SECURITY DEFINER functions executable by `anon`.
- 53 SECURITY DEFINER RPCs remain executable by `authenticated`. These are application RPCs; their access checks must continue to be reviewed individually. Do not mass-revoke them because matchmaking, chat, calls, profiles, moderation, shop, and trades depend on them.
- Anonymous-access policy notices remain for guest-play and intentionally public-read features, plus the two `cron` extension tables. These need feature-by-feature review rather than blanket removal.
- Leaked Password Protection remains disabled because Supabase lists it as Pro Plan and above. The 8-character signup check is not a substitute for Have I Been Pwned password screening.

### Performance

- 14 unindexed foreign keys.
- 16 Auth/RLS initialization-plan notices.
- 39 indexes currently reported unused.
- The two multiple-permissive-policy warnings were removed by consolidating global-chat reads and splitting moderator update-log writes from public reads.

### Health

- No Health Advisor findings.

## Not claimed as tested

The database ACLs, RLS state, Edge Function deployment states, and GitHub wiring were verified. A full browser end-to-end test of login, radio startup, skip voting, and station advancement was not performed in this audit. The new Edge Functions should be exercised from the live website and their runtime logs reviewed before calling the entire flow production-tested.

## Useful links

- [Supabase Security Advisor](https://supabase.com/dashboard/project/upghyzhawctughyojwpo/advisors/security)
- [Supabase Performance Advisor](https://supabase.com/dashboard/project/upghyzhawctughyojwpo/advisors/performance)
- [Supabase Health Advisor](https://supabase.com/dashboard/project/upghyzhawctughyojwpo/advisors/health)
- [Swiper repository](https://github.com/playswiper/Swiper)
- [Supabase password security documentation](https://supabase.com/docs/guides/auth/password-security)
