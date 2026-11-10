-- Execute uma única vez no Supabase SQL Editor.
-- Somente a conta principal pode listar, aprovar ou bloquear usuários.
begin;
create or replace function public.zziping_admin_principal()
returns boolean language sql stable security definer set search_path=''
as $$
 select exists (
   select 1 from auth.users u
   join public.usuarios_autorizados a on a.usuario_id=u.id
   where u.id=(select auth.uid())
     and lower(u.email)='marcosjunior_81@hotmail.com'
     and a.administrador=true and a.ativo=true
 );
$$;
revoke all on function public.zziping_admin_principal() from public,anon;
grant execute on function public.zziping_admin_principal() to authenticated;

create or replace function public.zziping_listar_usuarios()
returns table(usuario_id uuid,email text,ativo boolean,administrador boolean,criado_em timestamptz)
language plpgsql security definer set search_path=''
as $$
begin
 if not public.zziping_admin_principal() then
   raise exception 'Acesso restrito ao administrador principal';
 end if;
 return query
 select u.id,u.email::text,coalesce(a.ativo,false),coalesce(a.administrador,false),u.created_at
 from auth.users u
 left join public.usuarios_autorizados a on a.usuario_id=u.id
 order by u.created_at desc;
end;
$$;
revoke all on function public.zziping_listar_usuarios() from public,anon;
grant execute on function public.zziping_listar_usuarios() to authenticated;

create or replace function public.zziping_definir_acesso(p_usuario_id uuid,p_ativo boolean)
returns void language plpgsql security definer set search_path=''
as $$
begin
 if not public.zziping_admin_principal() then
   raise exception 'Acesso restrito ao administrador principal';
 end if;
 if p_usuario_id=(select auth.uid()) then
   raise exception 'Não é permitido alterar seu próprio acesso';
 end if;
 if not exists(select 1 from auth.users where id=p_usuario_id) then
   raise exception 'Usuário não encontrado';
 end if;
 insert into public.usuarios_autorizados(usuario_id,administrador,ativo)
 values(p_usuario_id,false,p_ativo)
 on conflict(usuario_id) do update set administrador=false,ativo=excluded.ativo;
end;
$$;
revoke all on function public.zziping_definir_acesso(uuid,boolean) from public,anon;
grant execute on function public.zziping_definir_acesso(uuid,boolean) to authenticated;

-- Evitar que clientes alterem diretamente as autorizações.
revoke all on public.usuarios_autorizados from anon,authenticated;
commit;
