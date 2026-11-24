const SUPABASE_URL=Deno.env.get("SUPABASE_URL")??"";
function keyMap(name:string):Record<string,string>{try{const v=JSON.parse(Deno.env.get(name)??"{}");return v&&typeof v==="object"?v:{}}catch{return {}}}
const secretMap=keyMap("SUPABASE_SECRET_KEYS"),publishableMap=keyMap("SUPABASE_PUBLISHABLE_KEYS");
const SERVICE_KEY=secretMap.default??Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")??Deno.env.get("SUPABASE_SECRET_KEY")??"";
const PUBLIC_KEYS=[publishableMap.default,...Object.values(publishableMap),Deno.env.get("SUPABASE_ANON_KEY"),Deno.env.get("SUPABASE_PUBLISHABLE_KEY"),"sb_publishable_z70GOIzu3F_xdxdJiVa48A_SqvrA6-b"].filter((v):v is string=>typeof v==="string"&&v.length>0);
const origins=new Set(["https://www.playswiper.com","https://playswiper.com","http://localhost:3000","http://127.0.0.1:5500"]);
const cors=(o:string|null)=>({"Access-Control-Allow-Origin":o&&origins.has(o)?o:"https://www.playswiper.com","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Access-Control-Max-Age":"86400","Vary":"Origin"});
function reply(o:string|null,s:number,b:Record<string,unknown>){return new Response(JSON.stringify(b),{status:s,headers:{...cors(o),"Content-Type":"application/json","Cache-Control":"no-store"}})}
async function hmac(v:string){const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(SERVICE_KEY),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const x=await crypto.subtle.sign("HMAC",k,new TextEncoder().encode(v));return [...new Uint8Array(x)].map(b=>b.toString(16).padStart(2,"0")).join("")}
function uuidFromHex(h:string){const x=h.slice(0,32).split("");x[12]="4";x[16]=((parseInt(x[16],16)&3)|8).toString(16);const s=x.join("");return s.slice(0,8)+"-"+s.slice(8,12)+"-"+s.slice(12,16)+"-"+s.slice(16,20)+"-"+s.slice(20)}
async function rest(path:string,init:RequestInit={}){const r=await fetch(SUPABASE_URL+"/rest/v1/"+path,{...init,headers:{"apikey":SERVICE_KEY,"Content-Type":"application/json","Accept":"application/json",...(init.headers??{})}});const raw=await r.text();let data:unknown=null;try{data=raw?JSON.parse(raw):null}catch{}return {ok:r.ok,status:r.status,data}}
async function rpc(name:string,args:Record<string,unknown>){const r=await rest("rpc/"+name,{method:"POST",body:JSON.stringify(args)});if(!r.ok)throw new Error("Radio backend request failed.");return r.data}
Deno.serve(async(req:Request)=>{
 const origin=req.headers.get("origin");
 if(req.method==="OPTIONS")return new Response("ok",{status:200,headers:cors(origin)});
 if(req.method!=="POST")return reply(origin,405,{error:"Method not allowed."});
 if(origin&&!origins.has(origin))return reply(origin,403,{error:"Origin not allowed."});
 if(!SUPABASE_URL||!SERVICE_KEY||!PUBLIC_KEYS.includes(req.headers.get("apikey")??""))return reply(origin,401,{error:"Request could not be verified."});
 if(Number(req.headers.get("content-length")??0)>2048)return reply(origin,413,{error:"Request is too large."});
 let body:{track_id?:unknown};try{body=await req.json()}catch{return reply(origin,400,{error:"Invalid skip vote."})}
 const trackId=typeof body.track_id==="string"?body.track_id:"";
 const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
 if(!uuid.test(trackId))return reply(origin,400,{error:"Invalid skip vote."});
 try{
  const trustedIp=req.headers.get("cf-connecting-ip");
  const isLocalOrigin=origin==="http://localhost:3000"||origin==="http://127.0.0.1:5500";
  if(!trustedIp&&!isLocalOrigin)return reply(origin,503,{error:"Security check unavailable. Please retry."});
  const ip=(trustedIp??"local-development").trim().slice(0,100);
  const ipHash=await hmac("swiper-radio-skip-ip:"+ip);
  const allowed=await rpc("swiper_username_login_rate_limit",{p_bucket_key:ipHash,p_limit:12,p_window_seconds:600});
  if(allowed!==true)return reply(origin,429,{error:"Too many skip votes from this connection. Try again later."});
  const voter=uuidFromHex(await hmac("swiper-radio-skip-voter:"+ip+":"+trackId));
  const inserted=await rest("radio_skip_votes",{method:"POST",headers:{"Prefer":"return=minimal"},body:JSON.stringify({track_id:trackId,voter_key:voter})});
  if(!inserted.ok&&inserted.status!==409)throw new Error("Vote could not be saved.");
  const since=new Date(Date.now()-600000).toISOString();
  const countResult=await rest("radio_skip_votes?select=id&track_id=eq."+encodeURIComponent(trackId)+"&created_at=gt."+encodeURIComponent(since));
  if(!countResult.ok||!Array.isArray(countResult.data))throw new Error("Vote count unavailable.");
  const count=countResult.data.length;
  let skipped=false;if(count>=3)skipped=(await rpc("radio_skip_if_voted",{p_expected_track_id:trackId}))===true;
  return reply(origin,200,{count,skipped,alreadyVoted:!inserted.ok});
 }catch(error){console.error("Radio skip vote failed:",error instanceof Error?error.message:"Unknown error");return reply(origin,503,{error:"Could not record your skip vote right now."})}
});