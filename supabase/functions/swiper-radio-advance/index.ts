const SUPABASE_URL=Deno.env.get("SUPABASE_URL")??"";
function map(name:string):Record<string,string>{try{const v=JSON.parse(Deno.env.get(name)??"{}");return v&&typeof v==="object"?v:{}}catch{return {}}}
const secrets=map("SUPABASE_SECRET_KEYS"),pub=map("SUPABASE_PUBLISHABLE_KEYS");
const SERVICE_KEY=secrets.default??Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")??Deno.env.get("SUPABASE_SECRET_KEY")??"";
const PUBLIC_KEYS=[pub.default,...Object.values(pub),Deno.env.get("SUPABASE_ANON_KEY"),Deno.env.get("SUPABASE_PUBLISHABLE_KEY"),"sb_publishable_z70GOIzu3F_xdxdJiVa48A_SqvrA6-b"].filter((v):v is string=>typeof v==="string"&&v.length>0);
const origins=new Set(["https://www.playswiper.com","https://playswiper.com","http://localhost:3000","http://127.0.0.1:5500"]);
const cors=(o:string|null)=>({"Access-Control-Allow-Origin":o&&origins.has(o)?o:"https://www.playswiper.com","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Access-Control-Max-Age":"86400","Vary":"Origin"});
function reply(o:string|null,s:number,b:Record<string,unknown>){return new Response(JSON.stringify(b),{status:s,headers:{...cors(o),"Content-Type":"application/json","Cache-Control":"no-store"}})}
async function hmac(v:string){const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(SERVICE_KEY),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const x=await crypto.subtle.sign("HMAC",k,new TextEncoder().encode(v));return [...new Uint8Array(x)].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function advance(id:string){const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/radio_advance_station",{method:"POST",headers:{"apikey":SERVICE_KEY,"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({p_expected_track_id:id})});if(!r.ok)throw new Error("Station advance failed.");return await r.json()}
Deno.serve(async(req:Request)=>{
 const origin=req.headers.get("origin");
 if(req.method==="OPTIONS")return new Response("ok",{status:200,headers:cors(origin)});
 if(req.method!=="POST")return reply(origin,405,{error:"Method not allowed."});
 if(origin&&!origins.has(origin))return reply(origin,403,{error:"Origin not allowed."});
 if(!SUPABASE_URL||!SERVICE_KEY||!PUBLIC_KEYS.includes(req.headers.get("apikey")??""))return reply(origin,401,{error:"Request could not be verified."});
 let body:{expected_track_id?:unknown};try{body=await req.json()}catch{return reply(origin,400,{error:"Invalid station request."})}
 const id=typeof body.expected_track_id==="string"?body.expected_track_id:"";
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id))return reply(origin,400,{error:"Invalid track ID."});
 try{
  const ip=(req.headers.get("cf-connecting-ip")??req.headers.get("x-real-ip")??req.headers.get("x-forwarded-for")?.split(",")[0]??"unknown").trim().slice(0,100);
  const bucket=await hmac("swiper-radio-advance-ip:"+ip);
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/swiper_username_login_rate_limit",{method:"POST",headers:{"apikey":SERVICE_KEY,"Content-Type":"application/json"},body:JSON.stringify({p_bucket_key:bucket,p_limit:30,p_window_seconds:900})});
  if(!r.ok||await r.json()!==true)return reply(origin,429,{error:"Too many station requests. Try again later."});
  const advanced=await advance(id);
  return reply(origin,200,{advanced:advanced===true});
 }catch(error){console.error("Radio advance failed:",error instanceof Error?error.message:"Unknown error");return reply(origin,503,{error:"Could not advance the radio right now."})}
});