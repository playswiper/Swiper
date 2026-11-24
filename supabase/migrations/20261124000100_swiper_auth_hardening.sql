-- Swiper security hardening — 2026-11-24
-- Existing application RPC grants remain unchanged. New public objects require explicit grants.

alter default privileges for role postgres in schema public
  revoke all on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke all on sequences from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;

-- Anonymous guest sessions must never be treated as members of private chats.
create or replace function public.swipe_conversation_member_names(p_conversation_id uuid)
returns table(user_id uuid, username text, display_name text)
language sql stable security definer set search_path = ''
as $function$
  select m.user_id, p.username, p.display_name
  from public.swipe_conversation_members m
  left join public.swipe_profiles p on p.id = m.user_id
  where (select auth.uid()) is not null
    and coalesce(((select auth.jwt())->>'is_anonymous')::boolean, false) = false
    and m.conversation_id = p_conversation_id
    and exists (
      select 1 from public.swipe_conversation_members mine
      where mine.conversation_id = p_conversation_id
        and mine.user_id = (select auth.uid())
        and mine.left_at is null
    )
  order by m.joined_at asc;
$function$;

create or replace function public.swipe_is_conversation_member(p_conversation_id uuid)
returns boolean
language sql stable security definer set search_path = ''
as $function$
  select (select auth.uid()) is not null
    and coalesce(((select auth.jwt())->>'is_anonymous')::boolean, false) = false
    and exists (
      select 1 from public.swipe_conversation_members m
      where m.conversation_id = p_conversation_id
        and m.user_id = (select auth.uid())
        and m.left_at is null
    );
$function$;

-- Moderator-only update log mutations explicitly reject anonymous sessions.
drop policy if exists "Moderators delete update logs" on public.swiper_update_logs;
create policy "Moderators delete update logs" on public.swiper_update_logs
for delete to authenticated using (
  (select auth.uid()) is not null
  and coalesce(((select auth.jwt())->>'is_anonymous')::boolean, false) = false
  and exists (select 1 from public.swiper_moderator_badges b where b.user_id = (select auth.uid()))
);

drop policy if exists "Moderators insert update logs" on public.swiper_update_logs;
create policy "Moderators insert update logs" on public.swiper_update_logs
for insert to authenticated with check (
  (select auth.uid()) is not null
  and coalesce(((select auth.jwt())->>'is_anonymous')::boolean, false) = false
  and exists (select 1 from public.swiper_moderator_badges b where b.user_id = (select auth.uid()))
);

drop policy if exists "Moderators update update logs" on public.swiper_update_logs;
create policy "Moderators update update logs" on public.swiper_update_logs
for update to authenticated
using (
  (select auth.uid()) is not null
  and coalesce(((select auth.jwt())->>'is_anonymous')::boolean, false) = false
  and exists (select 1 from public.swiper_moderator_badges b where b.user_id = (select auth.uid()))
)
with check (
  (select auth.uid()) is not null
  and coalesce(((select auth.jwt())->>'is_anonymous')::boolean, false) = false
  and exists (select 1 from public.swiper_moderator_badges b where b.user_id = (select auth.uid()))
);


-- Guest sessions may play, but must not read or participate in global chat.
drop policy if exists "Global chat messages are publicly readable" on public.swiper_global_chat_messages;
drop policy if exists "Global chat messages are readable by authenticated sessions" on public.swiper_global_chat_messages;
create policy "Global chat messages are readable by registered players"
on public.swiper_global_chat_messages for select to authenticated
using (
  (select auth.uid()) is not null
  and coalesce(((select auth.jwt())->>'is_anonymous')::boolean, false) = false
);


-- Private username-login audit trail.
-- Swiper username-login audit storage.
-- The private table is intentionally unavailable to anon/authenticated clients.
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

