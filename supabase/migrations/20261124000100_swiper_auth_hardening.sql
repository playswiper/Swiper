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
