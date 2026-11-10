// Supabase Edge Function: excluir-usuario
// Deploy no projeto Supabase. Nunca exponha SUPABASE_SERVICE_ROLE_KEY no site.
import { createClient } from 'npm:@supabase/supabase-js@2';
Deno.serve(async (req) => {
 const headers={'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'authorization, apikey, content-type','Access-Control-Allow-Methods':'POST, OPTIONS'};
 if(req.method==='OPTIONS')return new Response('ok',{headers});
 const respond=(status:number,message:string)=>new Response(JSON.stringify({message}),{status,headers});
 if(req.method!=='POST')return respond(405,'Método não permitido');
 try{
  const url=Deno.env.get('SUPABASE_URL')!;
  const publishable=Deno.env.get('SUPABASE_ANON_KEY')!;
  const secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  if(!url||!publishable||!secret)return respond(500,'Configuração do servidor incompleta');
  const authHeader=req.headers.get('Authorization')||'';
  if(!authHeader.startsWith('Bearer '))return respond(401,'Sessão necessária');
  const userClient=createClient(url,publishable,{global:{headers:{Authorization:authHeader}},auth:{persistSession:false}});
  const {data:{user},error:authError}=await userClient.auth.getUser();
  if(authError||!user)return respond(401,'Sessão inválida');
  const {data:isOwner,error:ownerError}=await userClient.rpc('zziping_admin_principal');
  if(ownerError||isOwner!==true)return respond(403,'Apenas o administrador principal pode excluir contas');
  const body=await req.json();
  const id=body?.usuario_id;
  if(typeof id!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id))return respond(400,'Identificador inválido');
  if(id===user.id)return respond(403,'Não é permitido excluir a própria conta');
  const admin=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:target,error:targetError}=await admin.auth.admin.getUserById(id);
  if(targetError||!target.user)return respond(404,'Usuário não encontrado');
  const {data:targetOwner,error:ownerCheckError}=await admin.from('usuarios_autorizados').select('administrador').eq('usuario_id',id).maybeSingle();
  if(ownerCheckError)return respond(500,'Não foi possível validar o usuário');
  if(targetOwner?.administrador)return respond(403,'Não é permitido excluir contas administrativas');
  // A exclusão pode falhar se houver FKs com RESTRICT em dados históricos.
  // Nesse caso, não removemos nem alteramos os registros históricos automaticamente.
  const {error:deleteError}=await admin.auth.admin.deleteUser(id);
  if(deleteError)return respond(409,'Não foi possível excluir sem afetar referências existentes: '+deleteError.message);
  return respond(200,'Conta excluída definitivamente');
 }catch(e){return respond(500,'Falha ao processar solicitação')}
});
