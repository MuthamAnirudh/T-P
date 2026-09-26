-- =====================================================================================
-- Gate Pass — single-use QR, enforced by the DATABASE (run once in Supabase → SQL Editor)
-- Safe to re-run. Fixes: "QR not expiring when scanned from other devices".
-- =====================================================================================

-- 1) Atomic redemption. Exactly ONE caller can ever flip qr_used false -> true; the row is
--    locked (FOR UPDATE) so two phones scanning in the same instant are serialised.
--    SECURITY DEFINER lets a guard's phone (no portal login, anon key) redeem a pass without
--    needing a broad UPDATE policy on the table.
create or replace function public.redeem_gate_pass(p_id bigint, p_token text, p_scanned_at text default null)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.gate_passes%rowtype;
  ts text := coalesce(nullif(p_scanned_at, ''), to_char(now() at time zone 'Asia/Kolkata', 'DD/MM/YYYY, HH12:MI:SS am'));
begin
  select * into r from public.gate_passes where id = p_id for update;
  if not found or p_token is null or r.qr_token is distinct from p_token then
    return jsonb_build_object('status', 'invalid');
  end if;
  if r.status is distinct from 'approved' then
    return jsonb_build_object('status', 'not_approved', 'pass', to_jsonb(r));
  end if;
  if coalesce(r.qr_used, false) then
    return jsonb_build_object('status', 'already_used', 'pass', to_jsonb(r));
  end if;
  update public.gate_passes
     set qr_used = true,
         data = jsonb_set(jsonb_set(coalesce(data, '{}'::jsonb), '{qrUsed}', 'true'::jsonb), '{qrUsedAt}', to_jsonb(ts))
   where id = p_id
   returning * into r;
  return jsonb_build_object('status', 'ok', 'pass', to_jsonb(r));
end;
$$;
revoke all on function public.redeem_gate_pass(bigint, text, text) from public;
grant execute on function public.redeem_gate_pass(bigint, text, text) to anon, authenticated;

-- 2) A used QR can never "come back to life". Any later save of a stale copy of the pass
--    (approval, guardian consent, admin edit, …) is prevented from resetting qr_used,
--    the scan timestamp, or rotating the token.
create or replace function public.gate_passes_keep_qr_used()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'UPDATE' and coalesce(old.qr_used, false) then
    new.qr_used := true;
    new.qr_token := old.qr_token;
    new.data := jsonb_set(coalesce(new.data, '{}'::jsonb), '{qrUsed}', 'true'::jsonb);
    if coalesce(old.data ->> 'qrUsedAt', '') <> '' then
      new.data := jsonb_set(new.data, '{qrUsedAt}', old.data -> 'qrUsedAt');
    end if;
  end if;
  return new;
end;
$$;
drop trigger if exists gate_passes_keep_qr_used on public.gate_passes;
create trigger gate_passes_keep_qr_used
  before update on public.gate_passes
  for each row execute function public.gate_passes_keep_qr_used();

-- 3) Realtime: lets a student's phone see "EXPIRED" the moment the guard scans.
--    (The app also polls every 3 s, so this is a bonus, not a requirement.)
do $$
begin
  alter publication supabase_realtime add table public.gate_passes;
exception when duplicate_object then null;
end $$;

-- 4) Public QR verification RPC. This is intentionally separate from the legacy RPC so the
-- standalone gate-pass-verify.html page never needs to receive guardian tokens, contact data,
-- internal workflow fields, or the complete gate_passes row. It still uses the same row lock,
-- making the first successful scan globally single-use across all devices/networks.
create or replace function public.redeem_gate_pass_public(p_id bigint, p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  r public.gate_passes%rowtype;
  ts text := to_char(now() at time zone 'Asia/Kolkata', 'DD/MM/YYYY, HH12:MI:SS am');
  safe jsonb;
begin
  select * into r from public.gate_passes where id = p_id for update;
  if not found or p_token is null or r.qr_token is distinct from p_token then
    return jsonb_build_object('status','invalid');
  end if;
  if r.status is distinct from 'approved' then
    return jsonb_build_object('status','not_approved');
  end if;
  if coalesce(r.qr_used,false) then
    return jsonb_build_object('status','already_used',
      'pass', jsonb_build_object('id',r.id,'qrUsedAt',r.data->>'qrUsedAt','studentName',r.data->>'studentName'));
  end if;
  update public.gate_passes
     set qr_used=true,
         data=jsonb_set(jsonb_set(coalesce(data,'{}'::jsonb),'{qrUsed}','true'::jsonb),'{qrUsedAt}',to_jsonb(ts))
   where id=p_id and qr_token=p_token and status='approved' and coalesce(qr_used,false)=false
   returning * into r;
  if not found then
    return jsonb_build_object('status','already_used',
      'pass', jsonb_build_object('id',r.id,'qrUsedAt',r.data->>'qrUsedAt','studentName',r.data->>'studentName'));
  end if;
  safe := jsonb_build_object(
    'id',r.id,
    'studentName',r.data->>'studentName',
    'rollNo',r.data->>'rollNo',
    'branch',r.data->>'branch',
    'destination',r.data->>'destination',
    'outDate',r.data->>'outDate',
    'outTime',r.data->>'outTime',
    'returnDate',r.data->>'returnDate',
    'returnTime',r.data->>'returnTime',
    'decidedBy',r.data->>'decidedBy',
    'decidedAt',r.data->>'decidedAt',
    'qrUsedAt',r.data->>'qrUsedAt',
    'studentPhoto',r.data->>'studentPhoto',
    'studentSignature',r.data->>'studentSignature'
  );
  return jsonb_build_object('status','ok','pass',safe);
end;
$$;
revoke all on function public.redeem_gate_pass_public(bigint,text) from public;
grant execute on function public.redeem_gate_pass_public(bigint,text) to anon, authenticated;
