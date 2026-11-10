-- ZZIPING: histórico automático de operações (execute no SQL Editor)
begin;
create table if not exists public.auditoria_operacoes (
  id bigint generated always as identity primary key,
  tabela text not null,
  registro_id text,
  operacao text not null check (operacao in ('INSERT','UPDATE','DELETE')),
  usuario_id uuid,
  usuario_email text,
  ocorrido_em timestamptz not null default now(),
  antes jsonb,
  depois jsonb
);
create index if not exists auditoria_operacoes_registro_idx on public.auditoria_operacoes(tabela,registro_id,ocorrido_em desc);
create index if not exists auditoria_operacoes_data_idx on public.auditoria_operacoes(ocorrido_em desc);
alter table public.auditoria_operacoes enable row level security;
revoke all on public.auditoria_operacoes from public,anon,authenticated;
grant select on public.auditoria_operacoes to authenticated;
drop policy if exists "Auditoria consulta autorizada" on public.auditoria_operacoes;
create policy "Auditoria consulta autorizada" on public.auditoria_operacoes
for select to authenticated using (public.usuario_autorizado());
create or replace function public.registrar_auditoria_zziping()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_antes jsonb; v_depois jsonb; v_id text;
begin
  if tg_op = 'INSERT' then
    v_depois = to_jsonb(new); v_id = new.id::text;
  elsif tg_op = 'UPDATE' then
    v_antes = to_jsonb(old); v_depois = to_jsonb(new); v_id = new.id::text;
    if v_antes = v_depois then return new; end if;
  else
    v_antes = to_jsonb(old); v_id = old.id::text;
  end if;
  insert into public.auditoria_operacoes(tabela,registro_id,operacao,usuario_id,usuario_email,antes,depois)
  values(tg_table_name,v_id,tg_op,auth.uid(),nullif(auth.jwt()->>'email',''),v_antes,v_depois);
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;
revoke all on function public.registrar_auditoria_zziping() from public,anon,authenticated;
drop trigger if exists auditar_prestadores_zziping on public.prestadores;
create trigger auditar_prestadores_zziping after insert or update or delete on public.prestadores
for each row execute function public.registrar_auditoria_zziping();
drop trigger if exists auditar_servicos_zziping on public.servicos;
create trigger auditar_servicos_zziping after insert or update or delete on public.servicos
for each row execute function public.registrar_auditoria_zziping();
drop trigger if exists auditar_baixas_zziping on public.baixas;
create trigger auditar_baixas_zziping after insert or update or delete on public.baixas
for each row execute function public.registrar_auditoria_zziping();
commit;
-- Eventos anteriores à instalação não podem ser recuperados por este mecanismo.
