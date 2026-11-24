-- Prevent clients from forging moderator-controlled and server-owned profile data.
-- SECURITY DEFINER admin/service operations remain able to update these fields.

create or replace function public.swipe_protect_moderation_fields()
returns trigger
language plpgsql
set search_path = ''
as $function$
begin
  if current_user in ('authenticated','anon') and (
       new.is_warned is distinct from old.is_warned
    or new.is_banned is distinct from old.is_banned
    or new.ban_days is distinct from old.ban_days
    or new.banned_until is distinct from old.banned_until
    or new.is_deleted is distinct from old.is_deleted
    or new.deleted_at is distinct from old.deleted_at
    or new.warned_setting is distinct from old.warned_setting
    or new.banned_setting is distinct from old.banned_setting
    or new.deleted_setting is distinct from old.deleted_setting
    or new.moderation_message is distinct from old.moderation_message
    or new.login_message_setting is distinct from old.login_message_setting
    or new.games_played is distinct from old.games_played
    or new.rank_name is distinct from old.rank_name
    or new.tournament_crowns is distinct from old.tournament_crowns
  ) then
    raise exception 'Protected account, moderation, and progression fields can only be changed by trusted server operations.'
      using errcode='42501';
  end if;
  return new;
end;
$function$;

create or replace function public.swipe_protect_profile_insert()
returns trigger
language plpgsql
set search_path = ''
as $function$
begin
  if current_user in ('authenticated','anon') then
    new.games_played := 0;
    new.rank_name := 'Unranked';
    new.tournament_crowns := 0;
    new.is_warned := false;
    new.is_banned := false;
    new.ban_days := 0;
    new.banned_until := null;
    new.is_deleted := false;
    new.deleted_at := null;
    new.warned_setting := 1;
    new.banned_setting := 1;
    new.deleted_setting := 1;
    new.is_verified := false;
    new.tomato_unlocked_setting := 1;
    new.avatar_tomato_setting := 1;
    new.avatar_preset := 'default';
    new.moderation_message := '';
    new.login_message_setting := 1;
    new.avatar_trail := 'none';
    new.equipped_emoji := null;
    new.created_at := now();
  end if;
  return new;
end;
$function$;

drop trigger if exists swipe_protect_profile_insert on public.swipe_profiles;
create trigger swipe_protect_profile_insert
before insert on public.swipe_profiles
for each row execute function public.swipe_protect_profile_insert();