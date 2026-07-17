"use strict";

const app = document.querySelector("#app");
const liveStatus = document.querySelector("#live-status");
const routes = new Set(["overview", "consensus", "compute", "nodes"]);
const endpoints = {overview:"/api/overview",consensus:"/api/consensus",compute:"/api/compute",nodes:"/api/nodes"};
let activeRoute = "overview";
let refreshTimer = null;
let selectedBlock = null;
let loadGeneration = 0;
let revealObserver = null;
const cache = new Map();

const esc = value => String(value ?? "—").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
const number = value => value === null || value === undefined ? "—" : Number(value).toLocaleString("en-US");
const short = (value, size=12) => value ? `${String(value).slice(0,size)}…${String(value).slice(-5)}` : "—";
const ago = ms => ms ? `${Math.max(0,Math.round((Date.now()-ms)/1000))}s ago` : "not reported";
const stateDot = state => `<i class="status-dot ${esc(state)}"></i>`;
const errors = data => Object.keys(data.errors || {}).length ? `<div class="error-banner">PARTIAL FEED · ${esc(Object.entries(data.errors).map(([k,v])=>`${k}: ${v}`).join(" · "))}</div>` : "";
const pageHead = (eyebrow,title,metrics) => `<header class="page-head"><div class="page-title"><span class="eyebrow">${esc(eyebrow)}</span><h1>${esc(title)}</h1></div>${metrics.map((m,index)=>`<div class="head-metric" style="--metric-delay:${80+index*70}ms"><span class="metric-label">${esc(m.label)}</span><span class="metric-value">${esc(m.value)}</span><span class="metric-sub">${esc(m.sub || "")}</span></div>`).join("")}</header>`;
const sectionHead = (label,note="") => `<div class="section-head"><span class="section-label">${esc(label)}</span><span class="section-note">${esc(note)}</span></div>`;
function announce(message){
  if(!liveStatus||liveStatus.textContent===message)return;
  liveStatus.textContent=message;
}

function lineChart(rows,key){
  const values=rows.map(row=>Number(row[key])).filter(Number.isFinite);
  if(values.length<2) return `<div class="chart-frame"><div class="chart-empty">AWAITING TELEMETRY</div></div>`;
  const min=Math.min(...values), max=Math.max(...values), span=max-min||1;
  const points=values.map((v,i)=>`${(i/(values.length-1)*100).toFixed(2)},${(94-(v-min)/span*78).toFixed(2)}`).join(" ");
  const last=points.split(" ").at(-1).split(",");
  return `<div class="chart-frame"><svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="${esc(key)} history"><polyline pathLength="1" points="${points}" fill="none" stroke="#3a352b" stroke-width="1.15" vector-effect="non-scaling-stroke"/><line x1="${last[0]}" y1="${last[1]}" x2="100" y2="${last[1]}" stroke="#b8340f" stroke-width=".7" stroke-dasharray="2 2" vector-effect="non-scaling-stroke"/><circle cx="${last[0]}" cy="${last[1]}" r="1.8" fill="#b8340f" vector-effect="non-scaling-stroke"/></svg></div>`;
}

function averageCadence(history){
  const changes=[];
  for(let i=1;i<history.length;i++){const delta=history[i].height-history[i-1].height;if(delta>0)changes.push((history[i].observed_ms-history[i-1].observed_ms)/delta)}
  if(!changes.length)return null;
  changes.sort((a,b)=>a-b);return changes[Math.floor(changes.length/2)];
}

function topologySvg(topology){
  const nodes=topology?.nodes||[],edges=topology?.edges||[];
  const positions=new Map();
  const validators=nodes.filter(node=>node.id.startsWith("validator-")).sort((a,b)=>a.id.localeCompare(b.id));
  const indexers=nodes.filter(node=>node.id.startsWith("indexer-")).sort((a,b)=>a.id.localeCompare(b.id));
  validators.forEach((node,index)=>positions.set(node.id,[14,18+index*(64/Math.max(1,validators.length-1))]));
  indexers.forEach((node,index)=>positions.set(node.id,[72,24+index*(52/Math.max(1,indexers.length-1))]));
  positions.set("finality",[45,50]);
  positions.set("gateway",[91,50]);
  const states=new Map(nodes.map(node=>[node.id,node.state]));
  const links=edges.map(([from,to])=>{
    const start=positions.get(from),end=positions.get(to);
    if(!start||!end)return "";
    const live=states.get(from)==="online"&&states.get(to)==="online";
    return `<line class="mesh-edge ${live?"motion-link":"is-muted"}" x1="${start[0]}" y1="${start[1]}" x2="${end[0]}" y2="${end[1]}"/>`;
  }).join("");
  const glyphs=nodes.map(node=>{
    const position=positions.get(node.id);if(!position)return "";
    const [x,y]=position,state=[...["online","catching_up","degraded","stalled","offline","unreported"]].includes(node.state)?node.state:"unreported";
    let glyph=`<circle cx="${x}" cy="${y}" r="3.2"/>`;
    if(node.id==="finality")glyph=`<rect x="${x-3.2}" y="${y-3.2}" width="6.4" height="6.4" transform="rotate(45 ${x} ${y})"/>`;
    else if(node.id.startsWith("indexer-"))glyph=`<rect x="${x-3}" y="${y-3}" width="6" height="6"/>`;
    else if(node.id==="gateway")glyph=`<circle cx="${x}" cy="${y}" r="4.1"/><circle class="mesh-core" cx="${x}" cy="${y}" r="1.5"/>`;
    return `<g class="mesh-node ${esc(state)}">${glyph}<text x="${x}" y="${y+8}" text-anchor="middle">${esc(node.label)}</text><title>${esc(node.label)} · ${esc(node.role)} · ${esc(state)}</title></g>`;
  }).join("");
  return `<svg viewBox="0 0 100 100" role="img" aria-label="Live validator, indexer, and observer topology">${links}${glyphs}</svg>`;
}

function renderOverview(data){
  const c=data.chain,h=data.history||[],cadence=averageCadence(h),lag=c.finalization_lag;
  const recent=h.slice(-60),heightMin=recent.length?recent[0].height:c.height;
  return `${pageHead("LIVE ENGINEERING NETWORK","Network Overview",[
    {label:"Unsafe head",value:number(c.height),sub:`slot ${number(c.slot)}`},
    {label:"Finalized epoch",value:number(c.finalized_epoch),sub:`lag ${number(c.finalization_lag)} epochs`},
    {label:"Median block",value:cadence?`${(cadence/1000).toFixed(1)}s`:"—",sub:"sampled locally"}
  ])}${errors(data)}<div class="content">
  <section class="section"><div class="instrument-grid"><div class="instrument">${sectionHead("Chain activity",`${number(h.length)} retained observations`)}${lineChart(h,"height")}<div class="axis-row"><span>${number(heightMin)} HEIGHT</span><span>NOW · ${number(c.height)}</span></div></div><div class="instrument">${sectionHead("Finality lag","epoch distance")}<div class="lag-scale"><div class="lag-rail"><i class="lag-dot" style="bottom:${Math.min(92,lag*3)}%"></i></div><div class="lag-read"><strong>${number(lag)}</strong><span>EPOCHS BEHIND HEAD</span><span>JUSTIFIED · ${number(c.justification_lag)}</span></div></div></div></div></section>
  <section class="section"><div class="instrument-grid"><div>${sectionHead("Block cadence",`${number(recent.length)} observations`)}<div class="cadence">${recent.map((row,i)=>`<i class="${i===recent.length-1?'latest':''}" style="height:${Math.max(8,Math.min(70,12+(row.height-heightMin)*2))}px"></i>`).join("")||'<div class="unavailable"><span>Awaiting sampled blocks</span></div>'}</div></div><div>${sectionHead("Mempool","operator feed")}<div class="lag-read"><strong>${number(c.mempool_transactions)}</strong><span>TRANSACTIONS · ${number(c.mempool_bytes)} BYTES</span></div></div></div></section>
  <section class="section"><div class="instrument-grid"><div>${sectionHead("Live network mesh","animated = reporting · dashed = unavailable")}<div class="topology">${topologySvg(data.topology)}</div><div class="topology-key"><span class="key-solid">live path</span><span class="key-dash">missing or degraded</span></div></div><div>${sectionHead("Service health",new Date(data.observed_ms).toLocaleTimeString())}<div class="service-list">${data.services.map(s=>`<div class="service service-${esc(s.state)}">${stateDot(s.state)}<span class="service-name">${esc(s.name)}</span><span class="service-detail">${esc(s.state)} · ${esc(s.detail)}</span></div>`).join("")}</div></div></div></section>
  <section class="section">${sectionHead("Chain identity","operator-reported")}${kvRows([["chain id",c.chain_id],["genesis hash",c.genesis_hash]])}</section></div>`;
}

function kvRows(rows){return `<dl>${rows.map(([k,v])=>`<div class="kv"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}</dl>`}

function blockDrawer(block){
  if(!block)return `<div class="drawer"><div class="stamp">SELECT A BLOCK</div><p class="hash">Choose a production ribbon tick or ledger row to inspect operator-reported fields.</p></div>`;
  return `<div class="drawer"><div class="stamp">UNSAFE BLOCK INSPECTION</div>${kvRows([["height",number(block.height)],["slot",number(block.slot)],["hash",block.hash],["parent",block.parent_hash],["timestamp",block.timestamp_ms?new Date(block.timestamp_ms).toISOString():null],["transactions",number((block.txids||[]).length)],["attestations","not reported by node set"]])}</div>`;
}

function quorumPanel(telemetry,validators=[]){
  if(telemetry?.state!=="reported")return `<div class="unavailable"><div><strong>VOTE TELEMETRY NOT REPORTED</strong><span>${esc(telemetry?.reason)}</span></div></div>`;
  const ordered=[...validators].sort((a,b)=>Number(a.witness_index)-Number(b.witness_index));
  return `<div class="quorum-panel"><div class="quorum-orbit" aria-label="${number(telemetry.online_validators)} of ${number(telemetry.total_validators)} validators reporting"><div class="quorum-core"><strong>${number(telemetry.threshold)}/${number(telemetry.total_validators)}</strong><span>QUORUM</span></div>${ordered.map((validator,index)=>`<div class="quorum-node q${index} ${esc(validator.state)}"><b>W${esc(validator.witness_index)}</b><span>${esc(validator.state)}</span></div>`).join("")}</div><div class="quorum-stats"><div><span>Accepted votes</span><strong>${number(telemetry.accepted)}</strong></div><div><span>Rejected votes</span><strong>${number(telemetry.rejected)}</strong></div><div><span>Pending votes</span><strong>${number(telemetry.pending_votes)}</strong></div><div><span>Pending certificates</span><strong>${number(telemetry.pending_certificates)}</strong></div></div></div>`;
}

function renderConsensus(data){
  const blocks=data.blocks||[]; if(!selectedBlock&&blocks.length)selectedBlock=blocks.at(-1);
  const pct=(data.epoch_progress*100).toFixed(1);
  return `${pageHead("CONSENSUS INSTRUMENT","Finality Operations",[
    {label:"Unsafe head",value:number(data.height),sub:`epoch ${number(data.current_epoch)}`},
    {label:"Justified",value:`E${number(data.justified_epoch)}`,sub:`lag ${number(data.justification_lag)}`},
    {label:"Finalized",value:`E${number(data.finalized_epoch)}`,sub:`lag ${number(data.finalization_lag)}`}
  ])}${errors(data)}<div class="content">
  <section class="section">${sectionHead("Finality pipeline",`epoch = floor(height / 256) · ${pct}% through E${number(data.current_epoch)}`)}<div class="pipeline"><div class="stage unsafe"><span class="metric-label">Unsafe</span><div class="metric-value">${number(data.height)}</div><span class="hash">${short(data.unsafe_head?.hash)}</span><div class="progress-track"><i style="width:${pct}%"></i></div></div><div class="connector"><span>${number(data.justification_lag)} EPOCH LAG</span></div><div class="stage justified"><span class="metric-label">Justified</span><div class="metric-value">E${number(data.justified_epoch)}</div><span class="hash">${short(data.justified?.hash)}</span></div><div class="connector"><span>${number(data.finalization_lag)} EPOCH LAG</span></div><div class="stage finalized"><span class="metric-label">Finalized</span><div class="metric-value">E${number(data.finalized_epoch)}</div><span class="hash">${short(data.finalized?.hash)}</span></div></div></section>
  <section class="section">${sectionHead("64-block production ribbon",data.median_block_cadence_ms?`median cadence ${(data.median_block_cadence_ms/1000).toFixed(1)}s`:"cadence unavailable")}<div class="ribbon">${blocks.map(block=>`<button data-block-index="${esc(block.height)}" class="${selectedBlock?.height===block.height?'selected':''}" title="block ${esc(block.height)}"></button>`).join("")}</div></section>
  <section class="section"><div class="split"><div><div class="table-scroll"><table class="ledger"><thead><tr><th>HEIGHT</th><th>SLOT</th><th>HASH</th><th>TX</th><th>TIME</th></tr></thead><tbody>${blocks.slice(-12).reverse().map(b=>`<tr data-block="${esc(b.height)}"><td>${number(b.height)}</td><td>${number(b.slot)}</td><td>${short(b.hash)}</td><td>${number((b.txids||[]).length)}</td><td>${b.timestamp_ms?new Date(b.timestamp_ms).toLocaleTimeString():"—"}</td></tr>`).join("")}</tbody></table></div></div><div id="block-drawer">${blockDrawer(selectedBlock)}</div></div></section>
  <section class="section"><div class="split quorum-split"><div>${sectionHead("Quorum participation","durable vote ingress · live validator reports")}${quorumPanel(data.quorum_telemetry,data.validators)}</div><div>${sectionHead("Chain identity","public testnet · no production authority")}${kvRows([["chain id",data.chain_id],["genesis",data.genesis_hash],["mode",data.environment]])}</div></div></section></div>`;
}

const stateName={0:"open",1:"claimed",2:"submitted",3:"settled",4:"cancelled"};
function renderCompute(data){
  const s=data.supply,counts=data.jobs_by_state||{},jobs=data.jobs||[],history=data.history||[];
  return `${pageHead("TEST-TOKEN ECONOMY","Compute Economy",[
    {label:"Active workers",value:number(s.active_workers),sub:`${number(s.gpu_workers)} GPU capable`},
    {label:"Completed units",value:number(s.completed_units),sub:"on-chain worker totals"},
    {label:"Settled value",value:number(data.settled_value),sub:data.currency}
  ])}${errors(data)}<div class="content">
  <section class="section">${sectionHead("Worker supply","reported on chain")}<div class="supply-band"><div class="supply-item"><span class="metric-label">Workers</span><div class="metric-value">${number(s.active_workers)}</div></div><div class="supply-item"><span class="metric-label">CPU threads</span><div class="metric-value">${number(s.cpu_threads)}</div></div><div class="supply-item"><span class="metric-label">Memory</span><div class="metric-value">${number(s.memory_mb)}<small> MB</small></div></div><div class="supply-item"><span class="metric-label">GPU capable</span><div class="metric-value">${number(s.gpu_workers)}</div></div></div></section>
  <section class="section">${sectionHead("Job state flow","current indexed ledger")}<div class="state-flow">${["open","claimed","submitted","settled"].map(name=>`<div class="state-step ${counts[name]?'active':''}"><strong>${number(counts[name])}</strong><span>${name}</span></div>`).join("")}</div></section>
  <section class="section"><div class="instrument-grid"><div>${sectionHead("Capacity sampling",`${number(history.length)} observations`)}${lineChart(history,"total_worker_threads")}<div class="axis-row"><span>CPU THREADS</span><span>UNSAMPLED TIME IS NOT INTERPOLATED</span></div></div><div>${sectionHead("Value settlement",data.currency)}<div class="waterfall"><div><span class="metric-label">Active escrow</span><div class="metric-value">${number(data.active_escrow)}</div></div><div class="waterfall-track"><i style="width:${Number(data.settled_value)>0?'100':'0'}%"></i></div></div><div class="disclosure">${esc(data.disclosure)} No monetary value is claimed or implied.</div></div></div></section>
  <section class="section">${sectionHead("Workload ledger",`${number(jobs.length)} indexed jobs`)}${jobs.length?`<div class="table-scroll"><table class="ledger"><thead><tr><th>JOB</th><th>STATE</th><th>WORKLOAD</th><th>UNITS</th><th>PRICE / UNIT</th><th>ESCROW</th></tr></thead><tbody>${jobs.map(j=>`<tr><td>${short(j.job||j.id)}</td><td>${esc(stateName[Number(j.state)]||`state ${j.state}`)}</td><td>${short(j.workload||j.input_root)}</td><td>${number(j.completed_units)}</td><td>${number(j.agreed_price_per_unit||j.max_price_per_unit)}</td><td>${number(j.escrow)}</td></tr>`).join("")}</tbody></table></div>`:`<div class="unavailable"><div><strong>NO JOBS INDEXED</strong><span>The workload ledger will populate when the public indexer reports jobs.</span></div></div>`}</section>
  <section class="section"><div class="disclosure">ENGINEERING NETWORK · ${esc(data.currency)} · ${esc(data.disclosure)} Values are protocol accounting units, not currency.</div></section></div>`;
}

function renderNodes(data){
  const validators=data.validators||[],indexers=data.indexers||[];
  const onlineValidators=validators.filter(node=>node.state==="online").length;
  const readyIndexers=indexers.filter(indexer=>indexer.ready===true).length;
  const nodeClass=node=>{
    if(node.state!=="online")return "is-offline";
    if(node.last_report_ms&&Date.now()-node.last_report_ms>600000)return "is-offline";
    if(node.last_report_ms&&Date.now()-node.last_report_ms>60000)return "is-stale";
    return "is-online";
  };
  const topologyNodes=[
    ...validators.map(node=>({id:node.id,label:`W${node.witness_index}`,role:node.role,state:node.state})),
    ...indexers.map((node,index)=>({id:`indexer-${index}`,label:`IDX ${index+1}`,role:"public indexer",state:node.state})),
    {id:"finality",label:"Finality",role:"3-of-4 quorum",state:onlineValidators>=3?"online":"degraded"},
    {id:"gateway",label:"Observer",role:"read gateway",state:data.nodes.some(node=>node.kind==="observer"&&node.state==="online")?"online":"degraded"}
  ];
  const topologyEdges=[
    ...validators.map(node=>[node.id,"finality"]),
    ...indexers.map((_,index)=>["finality",`indexer-${index}`]),
    ["finality","gateway"]
  ];
  return `${pageHead("PUBLIC TESTNET CONTROL PLANE","Live Node Fleet",[
    {label:"Validators",value:`${number(onlineValidators)}/${number(validators.length)}`,sub:"reporting now"},
    {label:"Indexers",value:`${number(readyIndexers)}/${number(indexers.length)}`,sub:"query-ready"},
    {label:"Active incidents",value:number(data.incidents.length),sub:"explicit source failures"}
  ])}${errors(data)}<div class="content">
  <section class="section">${sectionHead("Fleet topology","four logical validators · three VM failure domains · one non-voting observer")}<div class="topology fleet-topology">${topologySvg({nodes:topologyNodes,edges:topologyEdges})}</div></section>
  <section class="section">${sectionHead("Validator and observer rail",`${number(data.nodes.length)} centrally visible`)}<div class="fleet">${data.nodes.map((node,index)=>{
    const glyph=node.kind==="validator"?`W${node.witness_index}`:node.kind==="observer"?"OBS":String(index+1).padStart(2,"0");
    const infrastructure=[node.region,node.zone?`zone ${node.zone}`:null,node.vm_size].filter(Boolean).join(" · ");
    const gossip=node.finality_gossip;
    const telemetry=gossip?`votes ${number(gossip.accepted)} accepted · ${number(gossip.rejected)} rejected`:String(node.telemetry_state||"").replaceAll("_"," ");
    return `<article class="node-row ${nodeClass(node)} kind-${esc(node.kind)}" data-node-id="${esc(node.id)}"><div class="node-glyph ${node.kind==="compute"?"worker":""}">${esc(glyph)}</div><div><div class="node-name">${esc(node.label)}</div><div class="node-role">${esc(node.role)}</div><div class="node-infrastructure">${esc(infrastructure)}</div></div><div>${kvRows([["state",node.state],["height",number(node.height)],["finalized",node.finalized_epoch===undefined?"—":`E${number(node.finalized_epoch)}`]])}</div><div class="node-telemetry">${esc(telemetry)}</div><div class="node-telemetry">${ago(node.last_report_ms)}</div></article>`;
  }).join("")||`<div class="unavailable"><span>NO NODE REPORTS</span></div>`}</div></section>
  <section class="section">${sectionHead("Public indexer plane",`${number(readyIndexers)} query-ready endpoints`)}<div class="indexer-rail">${indexers.map((indexer,index)=>`<article class="indexer-row ${esc(indexer.state)}"><div><b>IDX ${index+1}</b><span>${esc(indexer.failure_domain)}</span></div><div>${stateDot(indexer.state)}${esc(indexer.state)}</div><dl><div><dt>UNSAFE</dt><dd>${number(indexer.unsafe_height)}</dd></div><div><dt>FINALIZED</dt><dd>${number(indexer.finalized_height)}</dd></div><div><dt>FRESHNESS</dt><dd>${indexer.freshness_ms>=0?`${number(indexer.freshness_ms)} ms`:"—"}</dd></div></dl></article>`).join("")||`<div class="unavailable"><span>NO INDEXER REPORTS</span></div>`}</div></section>
  <section class="section">${sectionHead("Fleet incidents","active source failures")}${data.incidents.length?data.incidents.map(incident=>`<div class="incident">${esc(incident.source).toUpperCase()} · ${esc(incident.detail)}</div>`).join(""):`<div class="empty-fleet">NO ACTIVE SOURCE INCIDENTS<br>All currently configured telemetry sources are reporting.</div>`}</section></div>`;
}

const renderers={overview:renderOverview,consensus:renderConsensus,compute:renderCompute,nodes:renderNodes};
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
function activateMotion({refresh=false,previousMetrics=[]}={}){
  revealObserver?.disconnect();
  const sections=[...app.querySelectorAll(".section")];
  app.dataset.route=activeRoute;
  app.classList.remove("route-enter","live-refresh");
  if(prefersReducedMotion.matches){
    sections.forEach(section=>section.classList.add("motion-visible"));
    return;
  }
  if(refresh){
    const metrics=[...app.querySelectorAll(".metric-value,.lag-read strong,.state-step strong")];
    metrics.forEach((metric,index)=>{
      if(previousMetrics[index]!==undefined&&previousMetrics[index]!==metric.textContent){
        metric.animate(
          [{transform:"translateY(0)",opacity:1},{transform:"translateY(-5px)",opacity:.3,offset:.42},{transform:"translateY(0)",opacity:1}],
          {duration:520,easing:"cubic-bezier(.22,1,.36,1)"}
        );
      }
    });
    sections.forEach(section=>section.classList.add("motion-visible"));
  }else{
    app.classList.add("route-enter");
    sections.forEach(section=>section.classList.add("motion-pending"));
    revealObserver=new IntersectionObserver(entries=>{
      entries.forEach(entry=>{
        if(!entry.isIntersecting)return;
        entry.target.classList.remove("motion-pending");
        entry.target.classList.add("motion-visible");
        revealObserver?.unobserve(entry.target);
      });
    },{threshold:.08,rootMargin:"0px 0px -7% 0px"});
    sections.forEach((section,index)=>{
      section.style.transitionDelay=`${Math.min(index,4)*55}ms`;
      revealObserver.observe(section);
    });
    setTimeout(()=>app.classList.remove("route-enter"),1200);
  }
  if(!refresh){
    app.querySelectorAll(".chart-frame svg polyline").forEach(path=>{
      const matrix=path.getScreenCTM();
      const length=path.getTotalLength()*Math.max(Math.abs(matrix?.a||1),Math.abs(matrix?.d||1));
      path.style.setProperty("--path-length",`${length}px`);
      path.classList.add("motion-path");
    });
    app.querySelectorAll(".topology svg line:not([stroke-dasharray])").forEach((line,index)=>{
      const length=line.getTotalLength();
      line.animate(
        [{strokeDasharray:`${length} ${length}`,strokeDashoffset:length,opacity:.15},{strokeDasharray:`${length} ${length}`,strokeDashoffset:0,opacity:1}],
        {duration:850+index*120,easing:"cubic-bezier(.16,1,.3,1)",fill:"both"}
      );
    });
    app.querySelectorAll(".ribbon button").forEach((button,index)=>{
      button.animate(
        [{transform:"scaleY(.12)",opacity:.12},{transform:"scaleY(1)",opacity:1}],
        {duration:520,delay:Math.min(index*12,620),easing:"cubic-bezier(.22,1,.36,1)",fill:"both"}
      );
    });
  }
  app.querySelectorAll(".capacity-bars i").forEach((bar,index)=>bar.style.setProperty("--bar-delay",`${index*80}ms`));
  app.querySelectorAll(".section,.chart-frame,.topology,.head-metric").forEach(surface=>{
    surface.addEventListener("pointermove",event=>{
      const box=surface.getBoundingClientRect();
      surface.style.setProperty("--pointer-x",`${((event.clientX-box.left)/box.width*100).toFixed(1)}%`);
      surface.style.setProperty("--pointer-y",`${((event.clientY-box.top)/box.height*100).toFixed(1)}%`);
    },{passive:true});
  });
}

async function loadRoute(route,{silent=false}={}){
  const requestedRoute=routes.has(route)?route:"overview";
  activeRoute=requestedRoute;
  const generation=++loadGeneration;
  document.querySelectorAll("a[data-route]").forEach(link=>link.classList.toggle("active",link.dataset.route===requestedRoute));
  if(!silent&&!cache.has(requestedRoute))app.innerHTML='<div class="boot"><span class="spinner"></span>ESTABLISHING INSTRUMENT FEED</div>';
  const previousMetrics=[...app.querySelectorAll(".metric-value,.lag-read strong,.state-step strong")].map(metric=>metric.textContent);
  const focusedBlock=document.activeElement?.dataset?.blockIndex||document.activeElement?.dataset?.block;
  try{
    const response=await fetch(endpoints[requestedRoute],{headers:{Accept:"application/json"},cache:"no-store"});
    if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const data=await response.json();
    if(generation!==loadGeneration||requestedRoute!==activeRoute)return;
    cache.set(requestedRoute,data);app.innerHTML=renderers[requestedRoute](data);
    document.querySelector("#rail-pulse")?.classList.add("live");document.querySelector("#rail-state").textContent="LIVE FEED";
    bindInteractions(data);
    if(!silent)announce(`${document.querySelector("h1")?.textContent || "Dashboard"} loaded`);
    activateMotion({refresh:silent,previousMetrics});
    if(focusedBlock)document.querySelector(`[data-block-index="${CSS.escape(focusedBlock)}"],[data-block="${CSS.escape(focusedBlock)}"]`)?.focus({preventScroll:true});
  }catch(error){
    if(generation!==loadGeneration||requestedRoute!==activeRoute)return;
    const previous=cache.get(requestedRoute);
    if(previous)app.innerHTML=`<div class="error-banner">STALE VIEW · ${esc(error.message)}</div>${renderers[requestedRoute](previous)}`;
    else app.innerHTML=`<div class="boot"><div><span class="eyebrow">FEED UNAVAILABLE</span><h1>${esc(error.message)}</h1><p class="hash">The dashboard does not invent replacement telemetry. Retrying automatically.</p></div></div>`;
    document.querySelector("#rail-pulse")?.classList.remove("live");document.querySelector("#rail-state").textContent="FEED LOST";
    announce(`Dashboard feed unavailable: ${error.message}`);
  }
  if(generation!==loadGeneration)return;
  clearTimeout(refreshTimer);refreshTimer=setTimeout(()=>loadRoute(activeRoute,{silent:true}),5000);
}
function bindInteractions(data){
  if(activeRoute!=="consensus")return;
  const blocks=data.blocks||[];
  const drawer=document.querySelector("#block-drawer");
  if(drawer){
    drawer.setAttribute("role","region");
    drawer.setAttribute("aria-label","Block inspection");
  }
  const selectBlock=element=>{
    const height=Number(element.dataset.blockIndex||element.dataset.block);
    selectedBlock=blocks.find(block=>Number(block.height)===height)||null;
    if(drawer){
      drawer.classList.remove("drawer-in");
      drawer.innerHTML=blockDrawer(selectedBlock);
      requestAnimationFrame(()=>drawer.classList.add("drawer-in"));
    }
    document.querySelectorAll("[data-block-index],[data-block]").forEach(item=>{
      const selected=Number(item.dataset.blockIndex||item.dataset.block)===height;
      item.classList.toggle("selected",selected);
      if(item.matches("button"))item.setAttribute("aria-pressed",String(selected));
    });
  };
  document.querySelectorAll("[data-block-index],[data-block]").forEach(element=>{
    const height=element.dataset.blockIndex||element.dataset.block;
    if(element.matches("button")){
      element.setAttribute("aria-label",`Inspect block ${height}`);
      element.setAttribute("aria-pressed",String(element.classList.contains("selected")));
    }else{
      element.tabIndex=0;
      element.setAttribute("role","button");
      element.setAttribute("aria-label",`Inspect block ${height}`);
    }
    element.addEventListener("click",()=>selectBlock(element));
    element.addEventListener("keydown",event=>{
      if(event.key!=="Enter"&&event.key!==" ")return;
      event.preventDefault();
      selectBlock(element);
    });
  });
}
function routeFromHash(){return location.hash.slice(1).split("/")[0]||"overview"}
window.addEventListener("hashchange",()=>{selectedBlock=null;loadRoute(routeFromHash())});
loadRoute(routeFromHash());
