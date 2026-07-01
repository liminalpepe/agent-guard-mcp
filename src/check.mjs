// Slopsquat Guard — package existence + slopsquat/typosquat risk for AI coding agents.
// Given a package name + ecosystem, returns: does it exist + a risk verdict (OK/SUSPICIOUS/DANGER).
// MVP heuristics: existence · typo-distance to popular packages · known-slop corpus · age · downloads.
// The hallucination/slop corpus is the compounding moat — every agent query can grow it.

const TOP_NPM = ["react","react-dom","lodash","axios","express","next","vue","typescript","webpack","chalk","commander","dotenv","jest","eslint","prettier","moment","uuid","redux","node-fetch","cors","mongoose","ws","yargs","glob","semver","tailwindcss","vite","esbuild","zod","prisma","puppeteer","playwright","openai","langchain","dayjs","ioredis","pg","knex"];
const TOP_PYPI = ["requests","numpy","pandas","flask","django","fastapi","pydantic","sqlalchemy","boto3","scipy","matplotlib","pytest","pillow","beautifulsoup4","scikit-learn","tensorflow","torch","transformers","openai","langchain","aiohttp","httpx","click","rich","tqdm","pyyaml","python-dotenv","celery","redis","huggingface_hub","uvicorn","starlette","poetry"];
// Seed corpus of known LLM-hallucinated / slopsquat names (compounds over time per query):
const SLOP_SEED = ["huggingface-cli","react-codeshift","requests-oauth","python-sqlite","node-ffmpeg","openai-python","gpt-3","langchain-community-tools","fast-csv-parser","pandas-utils","torch-utils"];

function lev(a,b){const m=a.length,n=b.length;const d=Array.from({length:m+1},(_,i)=>{const r=new Array(n+1).fill(0);r[0]=i;return r;});for(let j=0;j<=n;j++)d[0][j]=j;for(let i=1;i<=m;i++)for(let j=1;j<=n;j++)d[i][j]=Math.min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(a[i-1]===b[j-1]?0:1));return d[m][n];}
async function j(url){try{const r=await fetch(url,{signal:AbortSignal.timeout(6000)});if(!r.ok)return{status:r.status};return{status:200,body:await r.json()};}catch(e){return{status:0,err:e.message};}}

async function npmInfo(name){
  const reg=await j(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  if(reg.status===404)return{exists:false};
  if(reg.status!==200)return{exists:null,err:reg.err||reg.status};
  const dl=await j(`https://api.npmjs.org/downloads/point/last-month/${encodeURIComponent(name)}`);
  return{exists:true,created:reg.body?.time?.created??null,monthlyDownloads:dl.body?.downloads??null};
}
async function pypiInfo(name){
  const r=await j(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if(r.status===404)return{exists:false};
  if(r.status!==200)return{exists:null,err:r.err||r.status};
  const dates=Object.values(r.body?.releases||{}).flat().map(f=>f.upload_time_iso_8601).filter(Boolean).sort();
  return{exists:true,created:dates[0]??null,monthlyDownloads:null};
}

export async function checkPackage(name,ecosystem="npm"){
  const top=ecosystem==="pypi"?TOP_PYPI:TOP_NPM;
  const info=ecosystem==="pypi"?await pypiInfo(name):await npmInfo(name);
  const flags=[];let risk=0;
  let nearest=null,nd=99;for(const t of top){const d=lev(name.toLowerCase(),t.toLowerCase());if(d<nd){nd=d;nearest=t;}}
  const isExactTop=nd===0;
  if(info.exists===false){
    risk=95;flags.push("DOES_NOT_EXIST — likely hallucinated or unregistered; do NOT install");
    if(nd>0&&nd<=2)flags.push(`looks like a typo of popular "${nearest}" (distance ${nd})`);
    return verdict(name,ecosystem,info,risk,flags,nearest,nd);
  }
  if(info.exists===null)return{name,ecosystem,exists:null,error:info.err,verdict:"UNKNOWN",risk:null};
  if(!isExactTop&&nd>0&&nd<=2){risk+=45;flags.push(`TYPOSQUAT risk: ${nd} char(s) from popular "${nearest}"`);}
  if(SLOP_SEED.includes(name.toLowerCase())){risk+=50;flags.push("matches known slop/hallucinated-name corpus");}
  if(info.created){const days=(Date.now()-new Date(info.created))/864e5;if(days<30){risk+=25;flags.push(`registered ${Math.round(days)}d ago (very new)`);}else if(days<90){risk+=10;flags.push(`registered ${Math.round(days)}d ago`);}}
  if(info.monthlyDownloads!=null){if(info.monthlyDownloads<50){risk+=20;flags.push(`near-zero downloads (${info.monthlyDownloads}/mo)`);}else if(info.monthlyDownloads>100000){risk-=15;flags.push("high downloads (established)");}}
  if(isExactTop){risk=Math.max(0,risk-40);flags.push(`exact match to popular "${nearest}"`);}
  return verdict(name,ecosystem,info,Math.max(0,Math.min(100,risk)),flags,nearest,nd);
}
function verdict(name,ecosystem,info,risk,flags,nearest,nd){
  const v=risk>=70?"DANGER":risk>=35?"SUSPICIOUS":"OK";
  return{name,ecosystem,exists:info.exists,risk,verdict:v,flags,nearest_popular:nearest,distance:nd,created:info.created??null,monthly_downloads:info.monthlyDownloads??null};
}

// CLI: node check.mjs <name> [ecosystem]
if(import.meta.url===`file://${process.argv[1]}`){
  const [,,name,eco="npm"]=process.argv;
  if(!name){console.log("usage: node check.mjs <package> [npm|pypi]");process.exit(1);}
  console.log(JSON.stringify(await checkPackage(name,eco),null,2));
}
