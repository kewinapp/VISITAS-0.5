const express=require('express'),{Pool}=require('pg'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path');
const SECRET=process.env.JWT_SECRET,DBURL=process.env.DATABASE_URL;
if(!SECRET||!DBURL){console.error('Defina JWT_SECRET e DATABASE_URL');process.exit(1)}
const pool=new Pool({connectionString:DBURL,ssl:/localhost|127\.0\.0\.1/.test(DBURL)?false:{rejectUnauthorized:false}});
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'100kb'}));
app.use((q,s,n)=>{s.set({'X-Frame-Options':'DENY','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});n()});
const tries=new Map();
function limit(q,s,n){const k=q.ip,now=Date.now(),t=tries.get(k)||{n:0,t:now};
  if(now-t.t>9e5){t.n=0;t.t=now}t.n++;tries.set(k,t);
  if(t.n>15)return s.status(429).json({erro:'Muitas tentativas. Aguarde alguns minutos.'});n()}
function auth(q,s,n){const m=(q.headers.cookie||'').match(/(?:^|; )tk=([^;]+)/);
  try{const p=jwt.verify(m&&m[1],SECRET);q.uid=p.uid;n()}catch(e){s.status(401).json({erro:'Sessão expirada'})}}
function login(q,s,u){const tk=jwt.sign({uid:u.id},SECRET,{expiresIn:'30d'});
  s.cookie('tk',tk,{httpOnly:true,sameSite:'lax',secure:q.secure,maxAge:2592e6});
  s.json({id:u.id,nome:u.name})}
app.get('/api/health',(q,s)=>s.send('ok'));
app.post('/api/register',limit,async(q,s)=>{
  const b=q.body||{},u=String(b.username||'').trim().toLowerCase(),nm=String(b.nome||'').trim(),pw=String(b.senha||'');
  if(!/^[a-z0-9._-]{3,30}$/.test(u))return s.status(400).json({erro:'Usuário: 3 a 30 letras minúsculas, números, ponto, hífen ou _'});
  if(nm.length<2||nm.length>60)return s.status(400).json({erro:'Informe seu nome'});
  if(pw.length<8)return s.status(400).json({erro:'A senha precisa ter ao menos 8 caracteres'});
  if(process.env.REGISTER_CODE&&b.codigo!==process.env.REGISTER_CODE)return s.status(403).json({erro:'Código de convite inválido'});
  try{const r=await pool.query('INSERT INTO users(username,name,pass) VALUES($1,$2,$3) RETURNING id,name',[u,nm,await bcrypt.hash(pw,10)]);login(q,s,r.rows[0])}
  catch(e){if(e.code==='23505')return s.status(409).json({erro:'Esse usuário já existe'});console.error(e);s.status(500).json({erro:'Erro no servidor'})}});
app.post('/api/login',limit,async(q,s)=>{
  const b=q.body||{};
  try{const r=await pool.query('SELECT id,name,pass FROM users WHERE username=$1',[String(b.username||'').trim().toLowerCase()]);
    const u=r.rows[0];if(!u||!await bcrypt.compare(String(b.senha||''),u.pass))return s.status(401).json({erro:'Usuário ou senha incorretos'});
    login(q,s,u)}catch(e){console.error(e);s.status(500).json({erro:'Erro no servidor'})}});
app.post('/api/logout',(q,s)=>{s.clearCookie('tk');s.json({ok:1})});
app.get('/api/me',auth,async(q,s)=>{const r=await pool.query('SELECT id,name FROM users WHERE id=$1',[q.uid]);
  r.rows[0]?s.json({id:r.rows[0].id,nome:r.rows[0].name}):s.status(401).json({erro:'Sessão expirada'})});
app.get('/api/visitas',auth,async(q,s)=>{
  const r=await pool.query('SELECT id,data FROM visitas WHERE user_id=$1 ORDER BY updated DESC',[q.uid]);
  s.json({visitas:r.rows.map(x=>({id:x.id,...x.data,viabiliza:x.data.viabiliza??x.data.obs??''}))})});
const F=['data','nome','cnpj','contato','segmento','lista','historia','fat','rec','pagBol','inv','cg','gar','viabiliza'];
app.put('/api/visitas/:id',auth,async(q,s)=>{
  if(!/^[\w-]{1,40}$/.test(q.params.id))return s.status(400).json({erro:'ID inválido'});
  const b=q.body||{},d={};F.forEach(k=>d[k]=String(b[k]??'').slice(0,2000));
  if(!['','Verde','Amarela','Cinza','Vermelha'].includes(d.lista))d.lista='';
  d.socios=(Array.isArray(b.socios)?b.socios:[]).slice(0,5).map(x=>String(x).slice(0,120));
  const cnpj=d.cnpj.replace(/\D/g,'');
  try{const r=await pool.query(`INSERT INTO visitas(id,user_id,cnpj,data,updated) VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(id) DO UPDATE SET cnpj=$3,data=$4,updated=$5 WHERE visitas.user_id=$2`,[q.params.id,q.uid,cnpj,d,Date.now()]);
    r.rowCount?s.json({ok:1}):s.status(403).json({erro:'Sem permissão'})}
  catch(e){console.error(e);s.status(500).json({erro:'Erro no servidor'})}});
app.delete('/api/visitas/:id',auth,async(q,s)=>{
  await pool.query('DELETE FROM visitas WHERE id=$1 AND user_id=$2',[q.params.id,q.uid]);s.json({ok:1})});
app.get('/api/cnpj/:c',auth,async(q,s)=>{
  const c=q.params.c.replace(/\D/g,'');if(c.length!==14)return s.status(400).json({erro:'CNPJ inválido'});
  const r=await pool.query(`SELECT u.name gerente,(u.id=$2) mine,v.data->>'nome' empresa,v.data->>'data' data
    FROM visitas v JOIN users u ON u.id=v.user_id WHERE v.cnpj=$1 ORDER BY v.updated DESC`,[c,q.uid]);
  s.json({res:r.rows})});
app.get('/api/resumo',auth,async(q,s)=>{
  const d=String(q.query.dia||'');if(!/^\d{4}-\d{2}-\d{2}$/.test(d))return s.status(400).json({erro:'Data inválida'});
  const r=await pool.query(`SELECT u.name gerente,(u.id=$2) mine,v.data->>'nome' nome,v.data->>'cnpj' cnpj,v.data->>'lista' lista,
    COALESCE(v.data->>'viabiliza',v.data->>'obs') viabiliza FROM visitas v JOIN users u ON u.id=v.user_id
    WHERE v.data->>'data'=$1 ORDER BY u.name,v.updated DESC`,[d,q.uid]);
  s.json({res:r.rows})});
app.use(express.static(path.join(__dirname,'public')));
(async()=>{
  await pool.query(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,pass TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS visitas(id TEXT PRIMARY KEY,user_id INT NOT NULL REFERENCES users(id),cnpj TEXT,data JSONB NOT NULL,updated BIGINT);
  CREATE INDEX IF NOT EXISTS visitas_cnpj ON visitas(cnpj)`);
  app.listen(process.env.PORT||3000,()=>console.log('ok'));
})().catch(e=>{console.error(e);process.exit(1)});
