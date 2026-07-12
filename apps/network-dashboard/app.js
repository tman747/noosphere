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

function topologySvg(nodes){
  const positions={producer:[18,50],indexer:[50,27],compute:[80,50],peers:[50,76]};
  const edges=[["producer","indexer"],["indexer","compute"],["producer","peers"]];
  return `<svg viewBox="0 0 100 100" role="img" aria-label="Reported network topology">${edges.map(([a,b])=>{const p=positions[a],q=positions[b];return `<line x1="${p[0]}" y1="${p[1]}" x2="${q[0]}" y2="${q[1]}" stroke="#3a352b" stroke-width=".5" ${b==="peers"?'stroke-dasharray="2 2"':''}/>`}).join("")}${nodes.map(node=>{const p=positions[node.id]||[50,50],un=node.state==="unreported";return `<g><${node.id==="compute"?"rect":"circle"} ${node.id==="compute"?`x="${p[0]-3}" y="${p[1]-3}" width="6" height="6"`:`cx="${p[0]}" cy="${p[1]}" r="3"`} fill="${un?'#f7f2e5':'#3a352b'}" stroke="#3a352b" stroke-width=".7" ${un?'stroke-dasharray="1 1"':''}/><text x="${p[0]}" y="${p[1]+9}" text-anchor="middle" font-family="Fira Code" font-size="3" fill="#3a352b">${esc(node.label).toUpperCase()}</text></g>`}).join("")}</svg>`;
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
  <section class="section"><div class="instrument-grid"><div>${sectionHead("Reported topology","solid = observed · dashed = unreported")}<div class="topology">${topologySvg(data.topology.nodes)}</div><div class="topology-key"><span class="key-solid">reported</span><span class="key-dash">unreported</span></div></div><div>${sectionHead("Service health",new Date(data.observed_ms).toLocaleTimeString())}<div class="service-list">${data.services.map(s=>`<div class="service">${stateDot(s.state)}<span class="service-name">${esc(s.name)}</span><span class="service-detail">${esc(s.state)} · ${esc(s.detail)}</span></div>`).join("")}</div></div></div></section>
  <section class="section">${sectionHead("Chain identity","operator-reported")}${kvRows([["chain id",c.chain_id],["genesis hash",c.genesis_hash]])}</section></div>`;
}

function kvRows(rows){return `<dl>${rows.map(([k,v])=>`<div class="kv"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}</dl>`}

function blockDrawer(block){
  if(!block)return `<div class="drawer"><div class="stamp">SELECT A BLOCK</div><p class="hash">Choose a production ribbon tick or ledger row to inspect operator-reported fields.</p></div>`;
  return `<div class="drawer"><div class="stamp">UNSAFE BLOCK INSPECTION</div>${kvRows([["height",number(block.height)],["slot",number(block.slot)],["hash",block.hash],["parent",block.parent_hash],["timestamp",block.timestamp_ms?new Date(block.timestamp_ms).toISOString():null],["transactions",number((block.txids||[]).length)],["attestations","not reported by node set"]])}</div>`;
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
  <section class="section"><div class="split"><div>${sectionHead("Quorum participation","certainty boundary")}<div class="unavailable"><div><strong>VOTE TELEMETRY NOT REPORTED</strong><span>${esc(data.quorum_telemetry?.reason)}</span></div></div></div><div>${sectionHead("Chain identity")}${kvRows([["chain id",data.chain_id],["genesis",data.genesis_hash]])}</div></div></section></div>`;
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

function capacity(node){const c=node.capacity;if(!c)return `<span class="node-telemetry">capacity not reported</span>`;return `<div class="capacity-bars" title="${number(c.cpu_threads)} threads · ${number(c.memory_mb)} MB"><i style="height:${Math.min(30,6+c.cpu_threads*5)}px"></i><i style="height:${Math.min(30,6+c.memory_mb/64)}px"></i><i style="height:${c.capabilities&2?30:6}px"></i></div><span class="micro">CPU · MEM · GPU</span>`}
function renderNodes(data){
  const online=data.nodes.filter(n=>n.state==="online").length;
  const nodeClass=node=>{
    if(node.state!=="online")return "is-offline";
    if(node.last_report_ms&&Date.now()-node.last_report_ms>600000)return "is-offline";
    if(node.last_report_ms&&Date.now()-node.last_report_ms>60000)return "is-stale";
    return "is-online";
  };
  return `${pageHead("CENTRAL REPORTING PLANE","Node Fleet",[
    {label:"Reported nodes",value:number(data.nodes.length),sub:`${number(online)} online`},
    {label:"Active incidents",value:number(data.incidents.length),sub:"source failures"},
    {label:"Unreported",value:"—",sub:"count unknown"}
  ])}${errors(data)}<div class="content">
  <section class="section">${sectionHead("Fleet topology","solid = reported · dashed = not centrally reported")}<div class="topology"><svg viewBox="0 0 100 100" aria-label="Node fleet topology"><line class="edge-confirmed" x1="20" y1="50" x2="51" y2="50" stroke="#3a352b" stroke-width=".6"/><line class="edge-expected" x1="51" y1="50" x2="80" y2="50" stroke="#3a352b" stroke-width=".6" stroke-dasharray="2 2"/><circle class="glyph-reported" cx="20" cy="50" r="4" fill="#3a352b"/><rect class="glyph-reported" x="47" y="46" width="8" height="8" fill="#3a352b"/><circle class="glyph-ghost" cx="80" cy="50" r="4" fill="#f7f2e5" stroke="#3a352b" stroke-width=".7" stroke-dasharray="1 1"/><text x="20" y="63" text-anchor="middle" font-family="Fira Code" font-size="3">PRODUCER</text><text x="51" y="63" text-anchor="middle" font-family="Fira Code" font-size="3">COMPUTE WORKER</text><text x="80" y="63" text-anchor="middle" font-family="Fira Code" font-size="3">MAC · UNREPORTED</text></svg></div></section>
  <section class="section">${sectionHead("Node comparison rail",`${number(data.nodes.length)} centrally visible`)}<div class="fleet">${data.nodes.map((n,i)=>`<article class="node-row ${nodeClass(n)}" data-node-id="${esc(n.id)}"><div class="node-glyph ${n.role.includes("worker")?"worker":""}">${String(i+1).padStart(2,"0")}</div><div><div class="node-name">${esc(n.label)}</div><div class="node-role">${esc(n.role)}</div></div><div>${kvRows([["state",n.state],["height",number(n.height)],["head",short(n.head_hash)]])}</div><div>${capacity(n)}</div><div class="node-telemetry">${esc(n.telemetry_state.replaceAll("_"," "))}<br>${ago(n.last_report_ms)}</div></article>`).join("")}<article class="node-row is-ghost"><div class="node-glyph">—</div><div><div class="node-name">Mac node</div><div class="node-role">node presence known locally</div></div><div class="node-telemetry">${esc(data.unreported.message)}</div><div class="unavailable"><span>SET UP CENTRAL REPORTER</span></div><div class="node-telemetry">not reported</div></article></div></section>
  <section class="section">${sectionHead("Fleet incidents","active source failures")}${data.incidents.length?data.incidents.map(x=>`<div class="incident">${esc(x.source).toUpperCase()} · ${esc(x.detail)}</div>`).join(""):`<div class="empty-fleet">NO ACTIVE SOURCE INCIDENTS<br>Unknown fleet telemetry remains explicitly unreported above.</div>`}</section></div>`;
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
