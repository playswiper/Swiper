-- Require a real signed-in moderator before privileged chat moderation RPCs.
-- The moderator badge remains the authorization boundary; anonymous sessions
-- are explicitly rejected before any moderation mutation is attempted.

create or replace function public.swiper_mod_resolve_chat_ban(
  p_user_id uuid,
  p_action text,
  p_note text default null
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if (select auth.uid()) is null
     or coalesce((select auth.jwt())->>'is_anonymous','false') <> 'false'
     or not exists (
       select 1 from public.swiper_moderator_badges b
       where b.user_id=(select auth.uid())
     ) then
    raise exception 'Moderator access required.' using errcode='42501';
  end if;

  if p_user_id is null then raise exception 'A target account is required.'; end if;
  if p_action not in ('restore','keep') then raise exception 'Unsupported review action.'; end if;

  update public.swiper_chat_moderation
  set permanent_chat_ban=case when p_action='restore' then false else permanent_chat_ban end,
      chat_banned_until=case when p_action='restore' then null else chat_banned_until end,
      warning_active=case when p_action='restore' then false else warning_active end,
      reviewed_at=now(), reviewed_by=(select auth.uid()),
      review_note=left(coalesce(p_note,''),500), updated_at=now()
  where user_id=p_user_id;

  return true;
end;
$function$;

create or replace function public.swiper_moderator_review_chat(
  target_user_id uuid,
  review_action text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if (select auth.uid()) is null
     or coalesce((select auth.jwt())->>'is_anonymous','false') <> 'false'
     or not exists (
       select 1 from public.swiper_moderator_badges b
       where b.user_id=(select auth.uid())
     ) then
    raise exception 'Moderator access required.' using errcode='42501';
  end if;

  if target_user_id is null then raise exception 'A target account is required.'; end if;
  if review_action not in ('restore_chat','clear_warning','restore_website') then
    raise exception 'Unsupported moderation action.';
  end if;

  insert into public.swiper_chat_moderation(user_id)
  values(target_user_id) on conflict(user_id) do nothing;

  if review_action='restore_chat' then
    update public.swiper_chat_moderation
       set permanent_chat_ban=false,chat_banned_until=null,warning_active=false,
           reviewed_at=now(),reviewed_by=(select auth.uid()),
           review_note='Restored by moderator review.',updated_at=now()
     where user_id=target_user_id;
    update public.swipe_profiles
       set is_warned=false,moderation_message=null
     where id=target_user_id and coalesce(is_banned,false)=false;
  elsif review_action='clear_warning' then
    update public.swiper_chat_moderation
       set warning_active=false,reviewed_at=now(),
           reviewed_by=(select auth.uid()),review_note='Warning cleared by moderator.',
           updated_at=now()
     where user_id=target_user_id;
    update public.swipe_profiles
       set is_warned=false,moderation_message=null
     where id=target_user_id and coalesce(is_banned,false)=false;
  else
    update public.swiper_chat_moderation
       set website_banned_until=null,reviewed_at=now(),
           reviewed_by=(select auth.uid()),
           review_note='Website suspension lifted by moderator.',updated_at=now()
     where user_id=target_user_id;
    update public.swipe_profiles
       set is_banned=false,banned_until=null,is_warned=false,moderation_message=null
     where id=target_user_id and banned_until is not null
       and banned_until<=now()+interval '1 hour';
  end if;
  return true;
end;
$function$;

revoke all on function public.swiper_mod_resolve_chat_ban(uuid,text,text) from public, anon;
grant execute on function public.swiper_mod_resolve_chat_ban(uuid,text,text) to authenticated, service_role;
revoke all on function public.swiper_moderator_review_chat(uuid,text) from public, anon;
grant execute on function public.swiper_moderator_review_chat(uuid,text) to authenticated, service_role;