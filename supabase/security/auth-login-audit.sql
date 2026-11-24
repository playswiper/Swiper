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
