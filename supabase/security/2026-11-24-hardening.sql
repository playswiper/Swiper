-- Swiper production security hardening
-- Applied to Supabase project upghyzhawctughyojwpo on 2026-11-24.
-- Re-runnable: CREATE OR REPLACE, IF EXISTS, and REVOKE/GRANT are intentional.

-- 1) Keep sensitive profile fields out of normal client SELECT queries.
revoke select on table public.swipe_profiles from authenticated;
grant select (
  id, username, created_at, avatar_color, avatar_shape,
  avatar_explosion_color, avatar_accent_color, display_name,
  avatar_image_url, games_played, rank_name, tournament_crowns,
  is_verified, avatar_trail, avatar_preset, equipped_emoji
) on table public.swipe_profiles to authenticated;

-- Client writes are column-scoped too. Server-owned moderation, score, reward,
-- verification, and preset-avatar fields cannot be set through table REST writes.
revoke insert, update, delete on table public.swipe_profiles from public, anon, authenticated;
grant insert (id, username, avatar_color, avatar_shape)
on table public.swipe_profiles to authenticated;
grant update (
 display_name, avatar_image_url, avatar_color, avatar_shape,
 avatar_accent_color, avatar_explosion_color, chat_rules_accepted_at
) on table public.swipe_profiles to authenticated;

create or replace function public.swipe_my_profile_private_state()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_uid uuid := auth.uid();
  v_state jsonb;
begin
  if v_uid is null then
    raise exception 'Sign in to read your private profile settings.';
  end if;

  select jsonb_build_object(
    'is_banned', p.is_banned,
    'banned_until', p.banned_until,
    'moderation_message', p.moderation_message,
    'login_message_setting', p.login_message_setting,
    'tomato_unlocked_setting', p.tomato_unlocked_setting,
    'avatar_tomato_setting', p.avatar_tomato_setting,
    'chat_rules_accepted_at', p.chat_rules_accepted_at
  )
  into v_state
  from public.swipe_profiles p
  where p.id = v_uid;

  if v_state is null then
    raise exception 'Your Swiper profile was not found.';
  end if;
  return v_state;
end;
$function$;

-- A thin wrapper must not add another SECURITY DEFINER privilege boundary.
alter function public.swiper_shop_open_crate(uuid) security invoker;

-- 2) Radio writes are server-only. Browser clients can read public station data,
--    but cannot inject tracks, queue entries, skip votes, or mutate station state.
revoke insert, update, delete on table public.radio_queue from public, anon, authenticated;
grant insert, update, delete on table public.radio_queue to service_role;
drop policy if exists "Players can request library tracks" on public.radio_queue;

revoke insert, update, delete on table public.radio_station from public, anon, authenticated;
grant insert, update, delete on table public.radio_station to service_role;

revoke insert, update, delete on table public.radio_tracks from public, anon, authenticated;
grant insert, update, delete on table public.radio_tracks to service_role;

revoke insert, update, delete on table public.radio_skip_votes from public, anon, authenticated;
grant insert on table public.radio_skip_votes to service_role;
drop policy if exists "Players can cast one skip vote per track" on public.radio_skip_votes;

revoke all on function public.radio_register_audius_track(text,text,text,text,integer) from public, anon, authenticated;
grant execute on function public.radio_register_audius_track(text,text,text,text,integer) to service_role;

revoke all on function public.radio_switch_to_audius(uuid) from public, anon, authenticated;
grant execute on function public.radio_switch_to_audius(uuid) to service_role;

revoke all on function public.radio_skip_if_voted(uuid) from public, anon, authenticated;
grant execute on function public.radio_skip_if_voted(uuid) to service_role;

revoke all on function public.radio_advance_station(uuid) from public, anon, authenticated;
grant execute on function public.radio_advance_station(uuid) to service_role;

-- 3) Remove privileges that bypass row-level security or are not needed by clients.
--    RLS does not protect TRUNCATE. Clients must never have TRUNCATE, REFERENCES,
--    or TRIGGER privileges on exposed public tables.
do $block$
declare
  r record;
begin
  for r in
    select c.oid::regclass as relation_name
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r','p')
  loop
    execute format(
      'revoke truncate, references, trigger on table %s from public, anon, authenticated',
      r.relation_name
    );
  end loop;
end;
$block$;

-- 4) Private, hashed login audit. No client role can read or write this table.
create table if not exists private.swiper_auth_login_audit (
  id bigint generated always as identity primary key,
  account_hash text not null check (account_hash ~ '^[a-f0-9]{64}$'),
  ip_hash text not null check (ip_hash ~ '^[a-f0-9]{64}$'),
  outcome text not null check (outcome in ('success','invalid_credentials','unknown_account','rate_limited')),
  attempted_at timestamptz not null default clock_timestamp()
);

create index if not exists swiper_auth_login_audit_attempted_at_idx
  on private.swiper_auth_login_audit (attempted_at desc);
create index if not exists swiper_auth_login_audit_account_attempted_idx
  on private.swiper_auth_login_audit (account_hash, attempted_at desc);

alter table private.swiper_auth_login_audit enable row level security;
revoke all on table private.swiper_auth_login_audit from public, anon, authenticated;
grant usage on schema private to service_role;

create or replace function public.swiper_auth_log_attempt(
  p_account_hash text,
  p_ip_hash text,
  p_outcome text
)
returns void
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if coalesce(current_setting('request.jwt.claim.role', true),'') <> 'service_role' then
    raise exception 'Not authorized.' using errcode='42501';
  end if;
  if p_account_hash is null or p_account_hash !~ '^[a-f0-9]{64}$'
     or p_ip_hash is null or p_ip_hash !~ '^[a-f0-9]{64}$'
     or p_outcome not in ('success','invalid_credentials','unknown_account','rate_limited') then
    raise exception 'Invalid audit event.';
  end if;

  insert into private.swiper_auth_login_audit(account_hash,ip_hash,outcome)
  values(p_account_hash,p_ip_hash,p_outcome);

  if random() < 0.02 then
    delete from private.swiper_auth_login_audit
    where attempted_at < clock_timestamp() - interval '30 days';
  end if;
end;
$function$;

revoke all on function public.swiper_auth_log_attempt(text,text,text) from public, anon, authenticated;
grant execute on function public.swiper_auth_log_attempt(text,text,text) to service_role;

-- 5) Keep the public outage-status RPC as an invoker wrapper. Its aggregate-only
--    implementation lives in the non-exposed private schema.
drop policy if exists swiper_auth_login_audit_service_role_only on private.swiper_auth_login_audit;
create policy swiper_auth_login_audit_service_role_only
on private.swiper_auth_login_audit
for all
to service_role
using (true)
with check (true);

create or replace function private.swiper_status_outage_report_status_internal()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_bucket bigint := floor(extract(epoch from now()) / 7200)::bigint;
  v_key text;
  v_count integer := 0;
  v_start timestamptz;
  v_end timestamptz;
begin
  v_start := to_timestamp(v_bucket * 7200);
  v_end := to_timestamp((v_bucket + 1) * 7200);
  v_key := encode(extensions.digest(lower('Swiper status outage report ' || v_bucket::text), 'sha256'), 'hex');
  select count(distinct r.user_id)::integer into v_count
  from public.swiper_community_issue_reports r
  where r.issue_key = v_key and r.created_at >= v_start and r.created_at < v_end;
  return jsonb_build_object(
    'report_count', v_count, 'threshold', 3,
    'outage_detected', v_count >= 3,
    'window_starts_at', v_start, 'window_ends_at', v_end
  );
end;
$function$;

grant usage on schema private to anon, authenticated;
revoke all on function private.swiper_status_outage_report_status_internal() from public;
grant execute on function private.swiper_status_outage_report_status_internal() to anon, authenticated;

create or replace function public.swiper_status_outage_report_status()
returns jsonb
language sql
stable
security invoker
set search_path = ''
as $function$
  select private.swiper_status_outage_report_status_internal();
$function$;

revoke all on function public.swiper_status_outage_report_status() from public;
grant execute on function public.swiper_status_outage_report_status() to anon, authenticated;

-- 6) Collapse redundant permissive SELECT policies without changing access.
drop policy if exists "Global chat messages are readable by anonymous sessions" on public.swiper_global_chat_messages;
drop policy if exists "Global chat messages are readable by signed-in players" on public.swiper_global_chat_messages;
drop policy if exists "Global chat messages are readable by authenticated sessions" on public.swiper_global_chat_messages;
create policy "Global chat messages are readable by authenticated sessions"
on public.swiper_global_chat_messages
for select
to authenticated
using ((select auth.uid()) is not null);

-- Keep public update-log reads, while moderator write actions remain badge-gated.
drop policy if exists "Moderators manage update logs" on public.swiper_update_logs;
drop policy if exists "Moderators insert update logs" on public.swiper_update_logs;
drop policy if exists "Moderators update update logs" on public.swiper_update_logs;
drop policy if exists "Moderators delete update logs" on public.swiper_update_logs;
create policy "Moderators insert update logs"
on public.swiper_update_logs
for insert
to authenticated
with check (exists (
  select 1 from public.swiper_moderator_badges b
  where b.user_id = (select auth.uid())
));
create policy "Moderators update update logs"
on public.swiper_update_logs
for update
to authenticated
using (exists (
  select 1 from public.swiper_moderator_badges b
  where b.user_id = (select auth.uid())
))
with check (exists (
  select 1 from public.swiper_moderator_badges b
  where b.user_id = (select auth.uid())
));
create policy "Moderators delete update logs"
on public.swiper_update_logs
for delete
to authenticated
using (exists (
  select 1 from public.swiper_moderator_badges b
  where b.user_id = (select auth.uid())
));

-- 7) Evaluate admin JWT claims once per statement in announcement policies.
drop policy if exists "Admin deletes announcements" on public.swiper_admin_announcements;
create policy "Admin deletes announcements"
on public.swiper_admin_announcements
for delete
to authenticated
using (
  (select auth.uid()) is not null
  and coalesce(((select auth.jwt())->>'is_anonymous')::boolean,false)=false
  and lower(coalesce((select auth.jwt())->>'email',''))='mystarsnight@gmail.com'
);

drop policy if exists "Admin publishes announcements" on public.swiper_admin_announcements;
create policy "Admin publishes announcements"
on public.swiper_admin_announcements
for insert
to authenticated
with check (
  (select auth.uid()) is not null
  and coalesce(((select auth.jwt())->>'is_anonymous')::boolean,false)=false
  and lower(coalesce((select auth.jwt())->>'email',''))='mystarsnight@gmail.com'
  and expires_at <= created_at + interval '11 seconds'
  and expires_at > created_at
);

-- 8) Score submission is authenticated and atomic. Clients cannot insert or
--    modify swipe_scores directly, and the legacy ranking helper is not public.
drop policy if exists "Registered players submit practice and bot scores" on public.swipe_scores;
revoke insert, update, delete on table public.swipe_scores from public, anon, authenticated;

drop trigger if exists swiper_shop_award_score_coins on public.swipe_scores;
drop function if exists private.award_swiper_shop_coins_for_score();

create or replace function public.swipe_submit_score(
  p_score integer,
  p_mode text,
  p_difficulty text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_uid uuid := auth.uid();
  v_username text;
  v_is_banned boolean;
  v_banned_until timestamptz;
  v_is_deleted boolean;
  v_score_id bigint;
  v_ranked jsonb;
begin
  if v_uid is null or coalesce((auth.jwt()->>'is_anonymous')::boolean, false) then
    raise exception 'Sign in with a registered Swiper account to submit scores.'
      using errcode = '42501';
  end if;
  if p_score is null or p_score < 0 or p_score > 1000000 then
    raise exception 'Score is outside the allowed range.';
  end if;
  if p_mode is null or p_mode not in ('practice','bot','quick') then
    raise exception 'Invalid leaderboard mode.';
  end if;
  if p_mode = 'bot' then
    if p_difficulty is null or p_difficulty not in ('easy','normal','hard','expert','impossible') then
      raise exception 'Choose a valid bot difficulty.';
    end if;
  elsif p_difficulty is not null then
    raise exception 'Difficulty is only valid for Bot Play.';
  end if;

  select p.username,coalesce(p.is_banned,false),p.banned_until,coalesce(p.is_deleted,false)
    into v_username,v_is_banned,v_banned_until,v_is_deleted
  from public.swipe_profiles p
  where p.id=v_uid
  for update;

  if not found or v_username is null or btrim(v_username)='' then
    raise exception 'Your Swiper profile was not found.';
  end if;
  if v_is_deleted then
    raise exception 'Deleted accounts cannot submit scores.';
  end if;
  if v_is_banned and (v_banned_until is null or v_banned_until>now()) then
    raise exception 'Banned accounts cannot submit scores.';
  end if;
  if exists (
    select 1 from public.swipe_scores s
    where s.user_id=v_uid
      and s.created_at>clock_timestamp()-interval '2 seconds'
  ) then
    raise exception 'Please wait a moment before submitting another score.';
  end if;

  insert into public.swipe_scores(player_name,score,mode,difficulty,user_id)
  values(v_username,p_score,p_mode,p_difficulty,v_uid)
  returning id into v_score_id;

  v_ranked:=public.swipe_record_game(p_score);
  return coalesce(v_ranked,'{}'::jsonb)||jsonb_build_object('score_id',v_score_id);
end;
$function$;

revoke all on function public.swipe_record_game(integer) from public, anon, authenticated;
revoke all on function public.swipe_submit_score(integer,text,text) from public, anon, authenticated;
grant execute on function public.swipe_submit_score(integer,text,text) to authenticated;

-- 9) Remove stale direct room-player write policies. Multiplayer state changes
--    are handled by scoped RPCs; authenticated clients have no table write grants.
drop policy if exists "Players update own room record" on public.swipe_room_players;
drop policy if exists "Signed-in users join rooms" on public.swipe_room_players;

-- The service-role-only policy documents the trusted multiplayer writer.
drop policy if exists swipe_room_players_service_role_all on public.swipe_room_players;
create policy swipe_room_players_service_role_all
on public.swipe_room_players
for all
to service_role
using (true)
with check (true);
