-- ZZIPING: exclusões restritas ao administrador principal.
-- Execute no Supabase SQL Editor. Excluir é irreversível: faça backup antes.
begin;
create or replace function public.zziping_excluir(p_tabela text,p_id text)
returns void language plpgsql security definer set search_path=''
as $$
declare v_id uuid;
begin
 if not public.zziping_admin_principal() then raise exception 'Somente o administrador principal pode excluir'; end if;
 if p_tabela='auditoria_operacoes' then
   delete from public.auditoria_operacoes where id=p_id::bigint;
 elsif p_tabela='baixas' then
   v_id:=p_id::uuid;
   delete from public.baixas where id=v_id;
 elsif p_tabela='servicos' then
   v_id:=p_id::uuid;
   delete from public.baixas where servico_id=v_id;
   delete from public.servicos where id=v_id;
 elsif p_tabela='prestadores' then
   v_id:=p_id::uuid;
   if exists(select 1 from public.servicos where prestador_id=v_id) then
     raise exception 'Este prestador possui serviços. Exclua primeiro os serviços relacionados.';
   end if;
   delete from public.prestadores where id=v_id;
 else raise exception 'Tipo de exclusão não permitido';
 end if;
end;
$$;
revoke all on function public.zziping_excluir(text,text) from public,anon;
grant execute on function public.zziping_excluir(text,text) to authenticated;
-- Exclusões diretas pela API ficam proibidas para funcionários comuns.
revoke delete on public.prestadores,public.servicos,public.baixas,public.auditoria_operacoes from authenticated,anon;
commit;
