const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
function parseKeyMap(name: string): Record<string,string> {
  try { const value=JSON.parse(Deno.env.get(name)??"{}"); return value&&typeof value==="object"?value:{}; }
  catch { return {}; }
}
const publishableMap=parseKeyMap("SUPABASE_PUBLISHABLE_KEYS");
const secretMap=parseKeyMap("SUPABASE_SECRET_KEYS");
const SERVICE_KEY=secretMap["default"]??Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")??Deno.env.get("SUPABASE_SECRET_KEY")??"";
const PUBLIC_KEYS=[
  publishableMap["default"],...Object.values(publishableMap),
  Deno.env.get("SUPABASE_ANON_KEY"),Deno.env.get("SUPABASE_PUBLISHABLE_KEY"),
  "sb_publishable_z70GOIzu3F_xdxdJiVa48A_SqvrA6-b",
].filter((v):v is string=>typeof v==="string"&&v.length>0);
const allowedOrigins=new Set(["https://www.playswiper.com","https://playswiper.com","http://localhost:3000","http://127.0.0.1:5500"]);
const APP="SwiperRadio";
const cors=(origin:string|null)=>({
  "Access-Control-Allow-Origin":origin&&allowedOrigins.has(origin)?origin:"https://www.playswiper.com",
  "Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods":"POST, OPTIONS",
  "Access-Control-Max-Age":"86400",
  "Vary":"Origin",
});
function reply(origin:string|null,status:number,body:Record<string,unknown>){
 return new Response(JSON.stringify(body),{status,headers:{...cors(origin),"Content-Type":"application/json","Cache-Control":"no-store"}});
}
async function hmac(value:string){
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(SERVICE_KEY),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const sig=await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(value));
 return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function serviceRpc(name:string,args:Record<string,unknown>){
 const r=await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`,{
  method:"POST",headers:{"apikey":SERVICE_KEY,"Content-Type":"application/json","Accept":"application/json"},
  body:JSON.stringify(args),
 });
 const raw=await r.text();let data:unknown=null;try{data=raw?JSON.parse(raw):null}catch{}
 if(!r.ok)throw new Error("Radio backend request failed.");
 return data;
}
Deno.serve(async(req:Request)=>{
 const origin=req.headers.get("origin");
 if(req.method==="OPTIONS")return new Response("ok",{status:200,headers:cors(origin)});
 if(req.method!=="POST")return reply(origin,405,{error:"Method not allowed."});
 if(origin&&!allowedOrigins.has(origin))return reply(origin,403,{error:"Origin not allowed."});
 if(!SUPABASE_URL||!SERVICE_KEY||PUBLIC_KEYS.length===0)return reply(origin,503,{error:"Radio is temporarily unavailable."});
 if(!PUBLIC_KEYS.includes(req.headers.get("apikey")??""))return reply(origin,401,{error:"Request could not be verified."});
 const length=Number(req.headers.get("content-length")??0);
 if(length>4096)return reply(origin,413,{error:"Request is too large."});
 let body:{provider_track_id?:unknown;activate?:unknown};
 try{body=await req.json()}catch{return reply(origin,400,{error:"Invalid track request."})}
 const id=typeof body.provider_track_id==="string"?body.provider_track_id.trim():"";
 if(!/^[a-zA-Z0-9_-]{1,100}$/.test(id))return reply(origin,400,{error:"Invalid track ID."});
 try{
  const ip=(req.headers.get("cf-connecting-ip")??req.headers.get("x-real-ip")??req.headers.get("x-forwarded-for")?.split(",")[0]??"unknown").trim().slice(0,100);
  const bucket=await hmac("swiper-radio-register-ip:"+ip);
  const allowed=await serviceRpc("swiper_username_login_rate_limit",{p_bucket_key:bucket,p_limit:80,p_window_seconds:900});
  if(allowed!==true)return reply(origin,429,{error:"Radio is receiving too many requests. Try again in 15 minutes."});

  const upstream=await fetch(`https://api.audius.co/v1/tracks/${encodeURIComponent(id)}?app_name=${APP}`,{headers:{"Accept":"application/json"}});
  if(!upstream.ok)return reply(origin,404,{error:"That Audius track could not be found."});
  const payload=await upstream.json().catch(()=>null);
  const track=Array.isArray(payload?.data)?payload.data[0]:payload?.data;
  if(!track||String(track.id)!==id||track.is_available===false)return reply(origin,404,{error:"That Audius track is unavailable."});
  const title=String(track.title??"Untitled").trim().slice(0,300)||"Untitled";
  const artist=String(track.user?.name??"Unknown artist").trim().slice(0,300)||"Unknown artist";
  const art=typeof track.artwork==="string"?track.artwork:(track.artwork?.["480x480"]??track.artwork?.["150x150"]??"");
  let artwork="";
  if(typeof art==="string"&&art.length<=2048){try{const u=new URL(art);if(u.protocol==="https:")artwork=u.toString()}catch{}}
  const duration=Math.max(1,Math.min(7200,Math.round(Number(track.duration)||180)));
  const saved=await serviceRpc("radio_register_audius_track",{
   p_provider_track_id:id,p_title:title,p_artist:artist,p_artwork_url:artwork,p_duration_seconds:duration
  });
  if(typeof saved!=="string")throw new Error("Track registration failed.");
  if(body.activate===true){
   await serviceRpc("radio_switch_to_audius",{p_track_id:saved});
  }
  return reply(origin,200,{id:saved,provider_track_id:id,title,artist,artwork_url:artwork,duration_seconds:duration});
 }catch(error){
  console.error("Radio track registration failed:",error instanceof Error?error.message:"Unknown error");
  return reply(origin,503,{error:"Could not register this radio track right now."});
 }
});