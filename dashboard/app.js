'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const sources = ['10.0.0.21', '10.0.0.22', '10.0.0.11'];
  const CLIENT='10.0.0.11',A3='10.0.0.23';
  const names = {'10.0.0.21':'Source A','10.0.0.22':'Source B','10.0.0.23':'Source C','10.0.0.11':'Protected client'};
  const detectorInfo = {threshold:['Two-window threshold','TwoWindowDetector','Fixed thresholds'],ewma:['EWMA control chart','EwmaDetector','Learned per-source baseline'],cusum:['CUSUM change detector','CusumDetector','Accumulated excess rate'],entropy:['Traffic-mix divergence','EntropyDetector','Change in who sends traffic']};
  const actionCaptions = {drop:'Drop the offender’s traffic',rate_limit:'Police each offender with a token bucket',graduated:'Rate-limit first, drop repeat offenders'};
  const fmt = (value, digits=0) => Number(value || 0).toLocaleString('en-US', {maximumFractionDigits:digits});
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const state = {page:'lab',mode:'simulation',scenario:'burst',mitigation:true,compare:false,clock:0,max:30,playing:false,speed:1,pps:600,capacity:1000,runs:null,recorded:null,bootstrap:null,lastTick:-1,lastJournal:'',noteTopic:'controller',notesOpen:false,notesKey:'',requestId:0,chartData:[],detector:'threshold',action:'drop',backoff:false,rateLimit:20,queueOn:false,queueSize:50,benchmark:null,reduced:matchMedia('(prefers-reduced-motion: reduce)').matches};
  const eventNames = {ratelimit_requested:'RATE LIMIT REQUESTED',ratelimit_confirmed:'MODELED RATE LIMIT APPLIED',attack_started:'TRAFFIC INCREASE',attack_ended:'SOURCES QUIET',alert:'SUSTAINED FLOOD DETECTED',drop_requested:'DROP RULE REQUESTED',drop_confirmed:'DROP RULES CONFIRMED',rule_expired:'RULE EXPIRED',drop_removed:'RULE REMOVED',switch_connected:'SWITCH CONNECTED',start:'GENERATOR STARTED',stop:'GENERATOR STOPPED'};
  const explain = {
    client:['A request worth protecting.','The normal client sends a small UDP message and expects an identical reply. Its fixed MAC, IPv4 address, and ingress port are bound together. Its address is excluded from the lab’s offender set.'],
    sources:['Many senders. One destination.','Source A and B offer traffic to the echo service. Source C is part of the original five-host topology; it stays in reserve except in the three-source flood and the flash crowd. In the Internet case, visible source addresses may be reflectors—not the attack initiator.'],
    controller:['The control plane.','The Python controller polls switch counters once per second, computes rates, and runs the selected detector. It tells the switch which precise flows to drop or rate-limit. It does not inspect every packet in an established forwarding flow.'],
    switch:['The data plane.','Open vSwitch forwards matching packets in the original lab. Priority-200 drop rules override priority-100 service forwarding rules. The dashboard models these decisions; only the recorded mode contains evidence from a real switch run.'],
    server:['An echo, not a web page.','This service receives a UDP payload on port 9000 and returns it unchanged. Successful replies and their round-trip times make connectivity easy to observe. Server pressure in model mode depends on an explicit assumed capacity.']
  };
  const protocolCopy = {
    udp:'<strong>UDP is the transport protocol.</strong> A sender puts a message into a datagram and sends it to a destination port. There is no TCP-style connection handshake, and UDP itself does not guarantee delivery. The echo application sends a reply, letting our client measure loss and round-trip time. The lab uses destination port <strong>9000</strong>; memcached reflection in the real incident used a different service, UDP <strong>11211</strong>.',
    ip:'<strong>IPv4 identifies the destination host; Ethernet delivers on the local link.</strong> The echo server is 10.0.0.10, with MAC 02:00:00:00:00:10. The strengthened lab controller checks IP/MAC consistency and the source’s expected ingress port. These fixed lab bindings are not Internet-wide authentication.',
    arp:'<strong>ARP asks: “Which local MAC address belongs to this IPv4 address?”</strong> A host broadcasts a lookup, then learns the responding host’s MAC. FlowGuard permits the necessary ARP traffic but validates its sender IP and hardware address, and retains those checks in learned switch rules. ARP discovery is different from broadcasting a victim-directed UDP packet.',
    openflow:'<strong>OpenFlow 1.3 is the controller–switch instruction channel.</strong> The controller reads per-flow counters and sends match/action rules. A forwarding rule says “send this traffic to that port.” A higher-priority mitigation rule says “drop this source’s UDP traffic to 10.0.0.10:9000 for 10 seconds.” A barrier confirms processing order; successful installation still needs error correlation or flow inspection.'
  };

  const seminarStories = {
    burst: 'Explain the green client and the quiet baseline. One busy window is allowed; a short spike is not enough evidence to block.',
    sustained: 'Play to 8 s with OFF. Toggle ON to compare the same traffic and watch the client recover. In this preset, rules expire at 17 s and 29 s.',
    pulsing: 'Play with the basic detector: quiet gaps reset its two-window count. Replay with CUSUM to show evidence accumulating across pulses.'
  };
  function renderSeminarGuide() {
    $$('[data-story]').forEach(button=>{const active=button.dataset.story===state.scenario;button.classList.toggle('active',active);button.setAttribute('aria-pressed',String(active));});
    $('story-prompt').textContent=seminarStories[state.scenario]||'Explore this extra case. Use the live numbers to explain what the detector sees, which rules apply, and what the client receives.';
    $('try-cusum').hidden=state.scenario!=='pulsing';
    $('try-cusum').textContent=state.detector==='cusum'?'Replay with basic detector':'Compare with CUSUM';
  }
  function updateMitigationControl() {
    $('mitigation').classList.toggle('on',state.mitigation);
    $('mitigation').setAttribute('aria-checked',String(state.mitigation));
    $('mitigation-state').textContent=state.mitigation?'ON':'OFF';
    $('mitigation-caption').textContent=state.mitigation?'Detect, then block the offenders':'Observe and alert; keep forwarding';
  }
  async function chooseStory(id) {
    if(!(id in seminarStories))return;
    state.scenario=id;state.detector='threshold';state.action='drop';state.backoff=false;
    state.pps=600;state.capacity=id==='burst'?2000:300;state.queueOn=id!=='burst';state.queueSize=50;
    state.mitigation=id!=='sustained';
    $('scenario').value=id;$('detector').value='threshold';$('detector-caption').textContent=detectorInfo.threshold[2];
    $('action').value='drop';$('action-caption').textContent=actionCaptions.drop;$('rate-limit').disabled=true;
    $('backoff').checked=false;$('queue-toggle').checked=state.queueOn;$('queue-size').disabled=!state.queueOn;
    for(const [input,key,output] of [['pps','pps','pps-value'],['capacity','capacity','capacity-value'],['queue-size','queueSize','queue-value']]){
      $(input).value=state[key];$(output).textContent=fmt(state[key]);
    }
    updateMitigationControl();closeComparison();
    await setMode('simulation');
  }
  function closeComparison() {
    state.compare=false;$('compare-region').hidden=true;$('compare-toggle').setAttribute('aria-pressed','false');
  }
  function toggleNotes(open) {
    state.notesOpen=open;
    $('technical-notes').classList.toggle('notes-floating',open);
    $('notes-toggle').setAttribute('aria-expanded',String(open));
    $('notes-close').hidden=!open;
    if(open){closeComparison();renderNotes();}
  }
  function selectNote(topic) {
    state.noteTopic=topic;state.notesKey='';
    $$('[data-note]').forEach(button=>{const active=button.dataset.note===topic;button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;});
    $('notes-content').setAttribute('aria-labelledby',`note-${topic}`);
    renderNotes();
  }
  function renderNotes() {
    const key=[state.noteTopic,state.mode,state.detector,state.action,state.backoff,state.queueOn].join(':');
    if(key===state.notesKey)return;state.notesKey=key;
    const detector=state.mode==='recorded'?'threshold':state.detector;
    const notes = {
      controller: `<h4>The controller decides. The switch enforces.</h4><ol><li><strong>Connect &amp; learn.</strong> OS-Ken speaks OpenFlow 1.3 to Open vSwitch. Initial allowed packets reach the controller via Packet-In; fixed IP/MAC/port bindings validate the lab hosts.</li><li><strong>Install forwarding.</strong> FlowMod rules send later matching packets through the switch. Established flows do not send every packet to Python.</li><li><strong>Poll &amp; decide.</strong> About every second, FlowStats replies provide packet counters. The detector turns counter differences into per-source rates.</li><li><strong>Enforce &amp; recover.</strong> Higher-priority, source-specific rules drop or meter the protected-service traffic. A hard timeout removes them automatically.</li></ol><p class="say-it">Say: “The controller is the decision maker; the switch is the fast forwarding and filtering point.”</p>`,
      protocols: `<h4>Two paths, different protocols.</h4><dl><div><dt>Data plane</dt><dd>Ethernet → IPv4 → UDP → echo payload. Victim <code>10.0.0.10:9000</code>; protected client <code>.11</code>; sources <code>.21 / .22 / .23</code>.</dd></div><div><dt>ARP / ICMP</dt><dd>ARP resolves local IPv4 addresses to MACs. ICMP ping checks baseline reachability; it is separate from the measured UDP service.</dd></div><div><dt>Control plane</dt><dd>OpenFlow 1.3 over TCP <code>6653</code>: Packet-In, FlowStats, FlowMod, Barrier and FlowRemoved messages between OS-Ken and OVS.</dd></div><div><dt>Probe &amp; browser</dt><dd>FGPB binary probes carry sequence/session/timestamp fields plus CRC32. Echo replies measure loss and RTT. CRC detects corruption; it is not authentication. HTTP <code>8765</code> serves this local interface.</dd></div></dl><p class="say-it">Say: “UDP carries the experiment traffic; TCP carries the controller’s OpenFlow messages.”</p>`,
      detection: `<h4>${esc(detectorInfo[detector][0])}</h4><p><code>packets/s = (current counter − previous counter) / elapsed seconds</code></p>${detector==='threshold'?'<p>The shipped rule requires <strong>victim &gt;100 packets/s</strong> and <strong>at least two eligible sources &gt;30 packets/s each</strong> for <strong>two consecutive high windows</strong>. A non-high window resets the run.</p><p>The protected client is excluded from offenders. A one-window burst is tolerated. A single source, a combined victim rate below threshold, or alternating pulses can evade this policy.</p>':detector==='cusum'?'<p>CUSUM accumulates standardised excess rate: <code>S = max(0, S + z − 0.5)</code>, with z clipped to ±4 and alarm threshold <code>S &gt; 6</code>. Shipped adaptive detectors first learn a short normal baseline.</p><p>With the quiet baseline in this model, one pulse contributes about 3.5. A quiet interval decays the evidence rather than erasing it, so a later pulse can cross 6. A baseline is learned, not a guarantee against every traffic pattern.</p>':`<p>${detector==='ewma'?'EWMA compares rates with a learned mean and variability; anomalous series are frozen so floods are not learned as normal.':'Traffic-mix divergence compares current source shares with a learned baseline using KL divergence, alongside volume and source checks.'}</p>`}<p class="say-it">Current detector: ${esc(detectorInfo[detector][1])}. The right-hand score belongs to this detector.</p>`,
      rules: `<h4>A narrow rule, with an expiry time.</h4><p>Service forwarding uses <strong>priority 100</strong>. Mitigation uses <strong>priority 200</strong> and matches UDP, the offender’s source IP, victim <code>10.0.0.10</code> and destination port <code>9000</code>. The protected client keeps its forwarding path.</p><dl><div><dt>Drop</dt><dd>No forwarding action: matching packets are discarded.</dd></div><div><dt>Rate-limit</dt><dd>An OVS packets/s meter polices the flow. The native gateway/model uses a Python token bucket instead.</dd></div><div><dt>Graduated / back-off</dt><dd>Rate-limit first, drop repeat offenders; optional repeat timeouts grow from 10 to 20, 40, then 80 seconds.</dd></div><div><dt>Expiry</dt><dd>Default hard timeout: 10 seconds. FlowRemoved reports removal; continued traffic can trigger another rule. A Barrier establishes ordering, so verify errors, flow tables, counters and endpoint results as well.</dd></div></dl><p class="say-it">Say: “We block the offending service flows temporarily, rather than disconnecting the whole network.”</p>`,
      evidence: `<h4>Hand off from explanation to measurement.</h4><dl><div><dt>This animation</dt><dd>Generated counters run through the actual detector classes. Motion, switch enforcement, queue capacity, client success and latency are modeled.</dd></div><div><dt>Native live lab</dt><dd>Real localhost UDP through a Python gateway. In this Windows FIFO trial, attack-phase loss was 60% OFF → 5% ON. One run, not an OVS result.</dd></div><div><dt>Linux switch lab</dt><dd>Vyas’s recorded M8 Mininet/OVS bottleneck trial: loss 70% OFF → 25% ON; p95 RTT 136.248 → 0.573 ms. Original M6 recordings had 80/80 client replies in both modes.</dd></div><div><dt>Teammates’ evidence</dt><dd>Show the correct Wireshark interface, UDP request/reply pairs, the attack phase, rule readback, OFF/ON loss/RTT and recovery. Identify each run’s platform and enforcement point.</dd></div></dl><p class="say-it">Handoff: “You have seen why the controller acts. Now we will verify what actually happened on the wire and at the switch.”</p>`,
      viva: `<h4>Answers to keep within reach.</h4><dl><div><dt>Why UDP?</dt><dd>Simple datagrams and an unchanged echo make packet rates, missing replies and RTT easy to measure. UDP itself does not guarantee delivery.</dd></div><div><dt>Why two windows?</dt><dd>Avoid acting on a brief spike, at the cost of detection delay. Pulsing traffic exposes that trade-off.</dd></div><div><dt>Why SDN?</dt><dd>Separate measurement/decision logic from switch enforcement; express precise, temporary match/action policies centrally.</dd></div><div><dt>What is new?</dt><dd>The reproducible integration, source attribution, comparisons and inspectable evidence. Thresholds, CUSUM, meters and CRC are established techniques.</dd></div><div><dt>What are the limits?</dt><dd>A small fixed-identity lab, configured protected client and limited trials. Local filtering cannot recover an upstream link already saturated before the filtering point.</dd></div></dl>`
    };
    $('notes-content').innerHTML=(state.mode==='recorded'?'<p class="say-it">These notes describe the current project. The original 13 Oct recordings predate the later hardening.</p>':'')+(notes[state.noteTopic]||notes.controller);
  }

  function toast(message) {
    $('toast').textContent=message; $('toast').hidden=false;
    clearTimeout(toast.timer); toast.timer=setTimeout(()=>$('toast').hidden=true,4300);
  }
  async function api(path,options) {
    const response=await fetch(path,options);
    const data=await response.json();
    if(!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }
  function navigate(page) {
    state.page=page;
    $$('.page').forEach(el=>{const active=el.id===`page-${page}`;el.hidden=!active;el.classList.toggle('active',active);});
    $$('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.page===page));
    if(page!=='lab') setPlaying(false);
    if(location.hash!==`#${page}`) history.replaceState(null,'',`#${page}`);
    window.scrollTo({top:0,behavior:'instant'});
    if(page==='lab') drawChart();
    if(page==='learn') loadBenchmark();
  }
  function setPlaying(playing) {
    state.playing=playing;
    $('play').innerHTML=playing?'Ⅱ <span>Pause the story</span>':'▶ <span>Play the story</span>';
    $('play').setAttribute('aria-label',playing?'Pause the story':'Play the story');
  }
  function currentRun() {return state.mode==='recorded'?state.recorded.trials[state.mitigation?'attack_on':'attack_off']:state.runs[state.mitigation?'on':'off'];}
  function frameAt(run,time) {
    if(!run?.frames?.length) return null;
    let frame=run.frames[0];
    for(const candidate of run.frames){if(candidate.t_s>time)break;frame=candidate;}
    return frame;
  }
  function recordedRules(run,time) {
    const rules=new Map();
    for(const event of run.events){
      if(event.t_s>time) break;
      if(event.type==='drop_requested') rules.set(event.source,{source:event.source,expires_at_s:event.t_s+(event.hard_timeout_s||10)});
      if(event.type==='drop_removed') rules.delete(event.source);
    }
    return [...rules.values()].filter(rule=>rule.expires_at_s>time);
  }
  function getFrame() {
    const run=currentRun();
    const frame=frameAt(run,state.clock);
    if(!frame) return null;
    if(state.mode!=='recorded') return frame;
    return {...frame,active_rules:recordedRules(run,state.clock)};
  }
  async function loadSimulation(reset=false) {
    const request=++state.requestId;
    const query=new URLSearchParams({scenario:state.scenario,pps:state.pps,capacity:state.capacity,detector:state.detector,action:state.action,backoff:state.backoff?1:0,rate_limit:state.rateLimit,queue:state.queueOn?state.queueSize:0});
    $('play').disabled=true;
    $('replay-workspace').setAttribute('aria-busy','true');
    try {
      const [on,off]=await Promise.all([api(`/api/simulation?${query}&mitigation=1`),api(`/api/simulation?${query}&mitigation=0`)]);
      if(request!==state.requestId)return;
      state.runs={on,off};state.max=on.timeline.duration_s;
      if(reset)state.clock=0;
      state.clock=Math.min(state.clock,state.max);
      $('timeline').max=state.max;
      $('play').disabled=false;state.lastJournal='';
      $('replay-workspace').dataset.loadedScenario=state.scenario;
      $('replay-workspace').setAttribute('aria-busy','false');
      updateTopology();updatePolicyNote();render(true);drawChart();
    } catch(error){toast(error.message);$('play').disabled=false;$('replay-workspace').setAttribute('aria-busy','false');}
  }
  async function setMode(mode) {
    setPlaying(false);state.requestId++;state.mode=mode;state.clock=0;state.lastJournal='';
    $$('.mode-tab').forEach(el=>{const active=el.dataset.mode===mode;el.classList.toggle('active',active);el.setAttribute('aria-selected',String(active));});
    $('replay-workspace').hidden=mode==='live';$('live-workspace').hidden=mode!=='live';
    $('scenario').disabled=mode==='recorded';$('settings-toggle').hidden=mode==='recorded';$('settings').hidden=true;
    $('settings-toggle').setAttribute('aria-expanded','false');
    $('model-metrics').hidden=mode!=='simulation';document.querySelector('.story-route').hidden=mode!=='simulation';document.querySelector('.seminar-cue').hidden=mode!=='simulation';closeComparison();toggleNotes(false);$('rule-pills').hidden=mode!=='simulation';
    if(mode!=='simulation'){updateTopology(true);restorePolicyNote();}
    if(mode==='live'){
      $('provenance').textContent='Real application messages on localhost. No switch, no flood, no simulated RTTs.';
      return;
    }
    if(mode==='recorded'){
      $('provenance').textContent='Original 13 Oct 2026 telemetry. Server capacity was not measured.';
      $('network-label').textContent='MOTION ILLUSTRATES RECORDED RATES';

      $('play').disabled=true;
      try{
        if(!state.recorded)state.recorded=await api('/api/recorded');
        if(state.mode!=='recorded')return;
        state.max=21;$('timeline').max=21;$('play').disabled=false;
        $('client-metric-label').textContent='RECORDED CLIENT REPLIES';
        render(true);drawChart();
      }catch(error){toast(error.message);$('play').disabled=false;}
    }else{
      $('provenance').textContent='Simulated traffic → the actual Python detector. No attack packets are sent.';
      $('network-label').textContent='ILLUSTRATIVE PACKET MOTION';

      $('client-metric-label').textContent='MODELED CLIENT REPLIES';
      await loadSimulation(true);
    }
  }
  function chapter(frame) {
    const t=state.clock,recorded=state.mode==='recorded';
    if(recorded){
      const latency=currentRun().summary.first_alert_latency_s;
      if(t<.2)return ['01','THE ORIGINAL EXPERIMENT','These are the original observations.','The two source generators start at t = 0. The animation follows saved victim counters. Compare traces opens the original receive-rate measurements.'];
      if(t<(latency||2))return ['02','THE OFFERED LOAD ARRIVES','The server receives the flood.','Two sources offer 600 packets/s each. The original controller observes rising flow counters.'];
      if(t<8 && state.mitigation)return ['03','A RECORDED MITIGATION DECISION','The switch filters the two sources.','The first alert is at 1.555 s; barrier confirmation is at 1.634 s. Inspect the actual event journal and recorded flow-rate observations.'];
      if(t<8)return ['03','DETECTION WITHOUT ENFORCEMENT','An alert alone changes no traffic.','Mitigation was disabled in this original run. The victim still receives approximately 1,200 attacker packets/s.'];
      if(frame.active_rules.length)return ['04','THE TRAFFIC PHASE HAS ENDED','The sources stop. The rules linger briefly.','The original traffic phase lasts eight seconds. Existing drop rules remain until their hard timeout expires.'];
      return ['05','RECORDED RECOVERY','Temporary rules are gone.','Both original runs delivered 80/80 legitimate replies. These data demonstrate filtering; they do not establish an availability improvement under saturation.'];
    }
    const summary=currentRun().summary||{},alerted=(summary.alert_count||0)>0,firstAlert=summary.first_alert_s;
    const rules=frame.active_rules||[],limited=rules.some(rule=>rule.action==='rate_limit'),det=detectorInfo[state.detector]||detectorInfo.threshold;
    const plainDrop=state.detector==='threshold'&&!limited;
    if(t<5)return ['01','ESTABLISH THE BASELINE','First, everything works.','The client sends small requests. The echo server sends them back. The controller counts quietly.'];
    if(state.scenario==='normal')return ['01','AN ORDINARY DAY','Small requests. Small replies.','Traffic remains below the detection thresholds. A normal client should not need a mitigation rule.'];
    const special=scenarioChapter(frame,t,{alerted,firstAlert,rules,limited,det});
    if(special)return special;
    if(state.scenario==='single-source' && t<26 && !alerted)return ['02','A DELIBERATE LIMITATION','One noisy source is not two.','The configured detector requires at least two qualifying source IPs. This single-source flood is deliberately left undetected.'];
    if(state.scenario==='low-rate' && t<26 && !alerted)return ['02','ANOTHER DELIBERATE LIMITATION','Under the threshold. Under the radar.','Each source sends 40 packets/s. Combined with the client, the victim rate is 90 packets/s—below the configured >100 threshold.'];
    if(state.scenario==='burst' && t<7)return ['02','BURST TOLERANCE','A spike is not yet a sustained flood.','Only one observation is high. The detector needs two consecutive high windows, so this brief burst does not trigger an alert.'];
    if(frame.active_rules.length && frame.drop_pps===0 && t<8)return plainDrop?['03','TWO WINDOWS. ONE DECISION.','Enough evidence to act.','Two sources exceeded 30 packets/s while the victim exceeded 100. The modeled drop rules now apply to the next forwarding interval.']:['03',state.detector==='threshold'?'TWO WINDOWS. ONE DECISION.':'ONE DETECTOR. ONE DECISION.','Enough evidence to act.',`The ${det[1]} named the offenders. Modeled ${limited?'rate-limit':'drop'} rules now apply to the next forwarding interval.`];
    if(frame.active_rules.length&&limited)return ['04','POLICE AT THE SWITCH','Slow the offenders. Keep the client.','The model passes each offender through a token bucket: a short burst, then the configured rate. The protected client is not limited. While a rule is installed the offender reads as 0 packets/s to the detector, as in the real controller.'];
    if(frame.active_rules.length)return ['04','ENFORCE AT THE SWITCH','Stop the offenders. Keep the client.','The model filters only those sources’ UDP traffic to port 9000. The protected client’s packets remain allowed. Rule expiry is visible in the journal.'];
    if(frame.high_windows===1&&state.detector!=='cusum')return ['02','FIRST QUALIFYING OBSERVATION','Suspicious. But wait one window.','The rate and source-count thresholds are met. Waiting for persistence avoids treating every short spike as a sustained attack.'];
    if(t>=26 || (state.scenario==='burst' && t>=7))return ['06','RECOVERY & REARMING','A quiet network can recover.','A non-high observation resets detection. Temporary rules expire automatically; a later wave can trigger a new decision.'];
    if(t>=17 && t<20 && state.mitigation)return ['05','THE HARD TIMEOUT','Ten seconds later, the rule expires.','Expiry avoids an indefinite block. If sources keep flooding, counters rise again and the detector can install another temporary rule.'];
    if(frame.detector_alert||(!state.mitigation && t>=7))return ['03','DETECTING IS NOT BLOCKING','An alarm alone does not stop a flood.','The detector can raise an alert, but with mitigation OFF the switch continues forwarding traffic. Toggle mitigation to compare the same modeled traffic.'];
    return ['02','TRAFFIC CHANGES','Two sources start talking at once.','The same offered traffic is used in both counterfactual runs. Toggle mitigation to compare enforcement at the same replay moment.'];
  }
  function attackOffered(frame) {return Object.entries(frame.source_offered_pps||{}).filter(([ip])=>ip!==CLIENT).reduce((sum,[,rate])=>sum+(rate||0),0);}
  function scenarioChapter(frame,t,{alerted,firstAlert,rules,limited,det}) {
    const scenario=state.scenario,beforeAlert=!alerted||t<firstAlert;
    if(scenario==='flash-crowd'){
      if(rules.length)return ['04','A FALSE ALARM','The rule hits busy, legitimate hosts.',`The ${det[1]} read the crowd as a flood, so the model now ${limited?'polices':'blocks'} hosts that were only busy. A volume rule cannot tell popularity from an attack; the traffic-mix detector sees the same mix and stays quiet.`];
      if(t<26)return ['02','A FLASH CROWD','More traffic is not always an attack.',`Every host, including the protected client, scales smoothly to 20× its usual rate with the same mix. ${alerted?'Watch whether this detector mistakes it for a flood.':'This detector does not alert: the mix of senders has not changed.'}`];
      return ['06','THE CROWD THINS','Traffic returns to normal.',alerted?'Rules installed during the crowd expire on their own timeout. Each one blocked legitimate traffic: the price of a false positive.':'No alert and no rule: legitimate load was left alone.'];
    }
    if(scenario==='pulsing'&&t<26&&!rules.length){
      if(!alerted)return ['02','ON, OFF, ON, OFF','A flood that never stays for two windows.','Both sources send 600 packets/s every other second, so no two consecutive windows are high and a persistence rule never fires. Try the CUSUM detector: its running sum carries evidence across the quiet seconds.'];
      if(t<firstAlert)return ['02','EVIDENCE ACCUMULATES','Short pulses add up.','Each pulse adds standardised excess rate to a running sum and a quiet second removes only a little. A few pulses push the sum past its alarm level, although no two consecutive windows are high.'];
    }
    if(scenario==='ramp'&&t<26&&!rules.length&&beforeAlert)return ['02','LOW AND SLOW','The flood creeps up.','Each source rises from 5 to 150 packets/s over 20 seconds. A fixed threshold trips once the rates cross it; a baseline that keeps learning can absorb a slow rise as “normal”.'];
    if(scenario==='three-source'&&t<26&&!rules.length&&beforeAlert)return ['02','THREE SOURCES','A third host joins the flood.','Source C (10.0.0.23) adds its own traffic. Every qualifying source is named in the alert and receives its own rule.'];
    if(scenario==='repeat-offender'){
      if(rules.length){const rule=rules.reduce((a,b)=>b.offense_count>a.offense_count?b:a);return ['04','REPEAT OFFENDER',`Offense ${rule.offense_count}: a ${rule.ttl_s}-second rule.`,state.backoff?'Back-off doubles the rule lifetime for each repeat offense the controller still remembers, so a later wave can meet a rule that is still installed.':'Without back-off every offense gets the same 10-second rule, so each new wave reaches the server until it is detected again. Turn on back-off and replay.'];}
      if(t>10&&attackOffered(frame)<100)return ['05','BETWEEN WAVES','The sources go quiet, then return.','The controller remembers each offender for 120 seconds after its rule ends. That memory is what lets back-off give a repeat offense a longer rule.'];
    }
    return null;
  }
  function render(force=false) {
    if(state.mode==='live'||!state.runs||(state.mode==='recorded'&&!state.recorded))return;
    const frame=getFrame();if(!frame)return;
    const tick=Math.floor(state.clock*5);
    if(!force&&tick===state.lastTick)return;
    state.lastTick=tick;
    const recorded=state.mode==='recorded';
    $('timeline').value=state.clock;$('clock').textContent=`${state.clock.toFixed(1).padStart(4,'0')} / ${state.max.toFixed(1)} s`;
    const story=chapter(frame);
    ['chapter-number','chapter-kicker','chapter-title','chapter-copy'].forEach((id,index)=>$(id).textContent=story[index]);
    $('moment-detail').textContent=momentDetail(frame);
    for(const [ip,id] of [['10.0.0.21','rate-a1'],['10.0.0.22','rate-a2'],['10.0.0.11','rate-client']]) $(id).textContent=`${fmt(frame.source_offered_pps[ip],0)} packets/s${recorded?'*':''}`;
    $('rate-a3').textContent=!recorded&&A3 in frame.source_offered_pps?`${fmt(frame.source_offered_pps[A3])} packets/s`:'';
    const rules=frame.active_rules||[];
    $('drop-marker').setAttribute('visibility',rules.length?'visible':'hidden');
    $('drop-marker').querySelector('text').textContent=rules.length&&rules.every(rule=>rule.action==='rate_limit')?'Policed here':'Blocked here';
    $('metric-delivered').textContent=fmt(frame.victim_delivered_pps);
    $('metric-dropped').textContent=recorded&&frame.drop_rate_available===false?'—':fmt(frame.drop_pps);
    $('metric-rules').textContent=rules.length?`${rules.length} ${recorded?'recorded':'modeled'} rules · ${Math.max(0,Math.ceil(Math.min(...rules.map(r=>r.expires_at_s))-state.clock))}s until expiry`:recorded||state.action==='drop'?'No active drop rules':'No active rules';
    if(recorded&&frame.drop_rate_available===false)$('metric-rules').textContent='First drop sample establishes a baseline';
    $('server-node').classList.toggle('overloaded',!recorded&&frame.server_load_ratio>1);
    $('server-state').textContent=recorded?'RECORDED OBSERVATION':frame.server_load_ratio>1?'MODELED OVERLOAD':rules.length?'PROTECTED':'HEALTHY';
    $('mobile-server-state').textContent=$('server-state').textContent;
    $('mobile-client-rate').textContent=`${fmt(frame.source_offered_pps['10.0.0.11'])} packets/s`;
    $('mobile-attack-rate').textContent=`${fmt((frame.source_offered_pps['10.0.0.21']||0)+(frame.source_offered_pps['10.0.0.22']||0)+(frame.source_offered_pps[A3]||0))} packets/s offered`;
    if(recorded){
      const measured=currentRun().summary.client;
      $('metric-load').textContent='Counter-derived rate · capacity unmeasured';
      $('metric-client').textContent=`${measured.received}/${measured.sent}`;
      $('metric-client').nextElementSibling.textContent=' replies';
      $('metric-latency').textContent='Whole original traffic phase · actual CSV';
      $('controller-state').textContent=rules.length?'Original drop rules active.':'Original recorded controller.';
    }else{
      $('metric-load').textContent=`${fmt(frame.server_load_ratio*100)}% of assumed capacity`;
      $('metric-client').textContent=fmt(frame.client_success*100);
      $('metric-client').nextElementSibling.textContent='%';
      $('metric-latency').textContent=frame.queue_delay_ms==null?`Illustrative RTT: ${fmt(frame.client_latency_ms,1)} ms`:`Modeled RTT: ${fmt(frame.client_latency_ms,1)} ms`;
      $('controller-state').textContent=rules.length?'Source-specific rules active.':frame.high_windows?'Checking sustained traffic.':'Watching, not blocking.';
      renderModelMetrics(frame,rules);
    }
    let windows=recorded?0:Math.min(frame.high_windows||0,2),windowLabel=recorded?'Original observations':`${windows} / 2 high windows`;
    const cusum=!recorded&&frame.detector_state&&frame.detector_state.cusum;
    if(cusum){const maxS=Math.max(0,...Object.values(cusum)),h=frame.detector_state.threshold_h;windows=maxS>h?2:maxS>h/2?1:0;windowLabel=`CUSUM ${fmt(maxS,1)} / alarm ${fmt(h,1)}`;}
    else if(!recorded){const need=currentRun().thresholds?.consecutive_windows||2;if(need!==2)windowLabel=`${Math.min(frame.high_windows||0,need)} / ${need} high windows`;}
    $$('#window-dots > circle').forEach((el,i)=>el.classList.toggle('filled',i<windows));
    $('window-dots').querySelector('text').textContent=windowLabel;
    renderJournal();renderSeminarGuide();renderNotes();updateChartCursor();
  }
  function detectorScore(frame) {
    const s=frame.detector_state||{},run=currentRun();
    if(s.cusum)return {value:Math.max(0,...Object.values(s.cusum)),digits:1,label:'CUSUM SUM (MAX)',note:`Largest running sum · alarm above ${fmt(s.threshold_h,1)}`};
    if(s.kl_bits!==undefined)return {value:s.kl_bits,digits:2,label:'MIX DIVERGENCE',note:`KL divergence in bits · alarm above ${fmt(s.kl_threshold_bits,2)}`};
    if(s.scores&&s.k_sigma!==undefined){const values=Object.entries(s.scores).filter(([ip])=>ip!==CLIENT).map(([,v])=>v);return {value:Math.max(0,...values),digits:1,label:'EWMA Z-SCORE (MAX)',note:`Largest source z-score · alarm above ${fmt(s.k_sigma,1)} σ`};}
    const limit=run.thresholds?.victim_pps||100;
    return {value:(frame.detector_input?.victim_pps||0)/limit,digits:2,label:'VICTIM RATE ÷ THRESHOLD',note:`Fixed rule: alarm above 1.00 (${fmt(limit)} packets/s); no learned score`};
  }
  function renderModelMetrics(frame,rules) {
    const queueOn=frame.queue_depth_packets!=null;
    $('model-metrics').classList.toggle('queue-off',!queueOn);
    $('metric-queue').textContent=queueOn?fmt(frame.queue_depth_packets,0):'—';
    $('metric-queue-note').textContent=queueOn?`of ${fmt(currentRun().parameters.queue_packets)} · modeled delay ${fmt(frame.queue_delay_ms,1)} ms`:'Queue model off · turn on “Bottleneck queue”';
    $('metric-queue-drops').textContent=queueOn?fmt(frame.queue_drops_pps,0):'—';
    $('metric-queue-drops-note').textContent=queueOn?`Arrivals beyond ${fmt(state.capacity)} packets/s and a full queue`:'Proportional-share formula in use';
    const score=detectorScore(frame);
    $('score-label').textContent=score.label;$('metric-score').textContent=fmt(score.value,score.digits);$('metric-score-note').textContent=score.note;
    $('rule-pills').innerHTML=rules.map(rule=>{
      const left=Math.max(0,Math.ceil(rule.expires_at_s-state.clock));
      const verb=rule.action==='rate_limit'?`rate-limited ${fmt(rule.rate_pps)} pps`:'dropped';
      return `<span class="rule-pill${rule.action==='rate_limit'?' limit':''}">${esc(rule.source)} · ${esc(verb)} · TTL ${fmt(rule.ttl_s)} s · ${left} s left${rule.offense_count>1?` · offense ${fmt(rule.offense_count)}`:''}</span>`;
    }).join('');
  }
  function momentDetail(frame) {
    if(state.mode==='recorded')return 'The recorded mode shows the unmodified original experiment. Source offered rates marked * are inferred from delivered flow rates plus recorded drop deltas. The victim chart uses separate victim.jsonl receive counts. Original client CSVs preserve timestamps and RTTs; Wireshark captures are shown separately by the team. Historical results predate the new controller hardening.';
    const input=frame.detector_input||{};
    const queueText=frame.queue_delay_ms==null?'':` A modeled ${fmt(currentRun().parameters.queue_packets)}-packet FIFO queue serves ${fmt(state.capacity)} packets/s; client success is the share of arrivals it does not drop.`;
    if(state.detector!=='threshold'){const score=detectorScore(frame);return `The actual ${detectorInfo[state.detector][1]} (controller/detectors.py) sees ${fmt(input.victim_pps)} packets/s for the protected service. ${score.note}: now ${fmt(score.value,score.digits)}. Sources under a modeled rule read as 0 packets/s to the detector, as in the real controller. Forwarding is modeled; no OpenFlow switch is contacted.${queueText} Animated motion is representative, not a measured packet capture.`;}
    if(queueText)return `The actual detector sees ${fmt(input.victim_pps)} packets/s for the protected service. ${frame.high_windows||0} consecutive high observations have occurred. Forwarding is modeled; no OpenFlow switch is contacted.${queueText} Animated motion is representative, not a measured packet capture.`;
    return `The actual detector sees ${fmt(input.victim_pps)} packets/s for the protected service. ${Object.entries(input.source_pps||{}).filter(([ip,rate])=>ip!=='10.0.0.11'&&rate>30).length} unprotected sources exceed 30 packets/s; ${frame.high_windows||0} consecutive high observations have occurred. Forwarding is modeled; no OpenFlow switch is contacted. Reply success assumes proportional sharing of an explicitly hypothetical ${fmt(state.capacity)} packets/s service capacity. Animated motion is representative, not a measured packet capture.`;
  }
  function eventMessage(event) {
    if(event.message)return `${event.source ? event.source+' · ' : ''}${event.message}`;
    if(event.type==='alert')return `${fmt(event.victim_pps)} victim packets/s. Sources: ${Object.keys(event.sources||{}).map(ip=>names[ip]||ip).join(', ')}.`;
    if(event.type==='drop_requested')return `${event.source} → 10.0.0.10:9000 · hard timeout ${event.hard_timeout_s}s.`;
    if(event.type==='drop_confirmed')return `Barrier reply for ${(event.sources||[]).join(', ')}. Historical confirmation label.`;
    if(event.type==='drop_removed')return `${event.source} · ${fmt(event.packets)} packets dropped before removal.`;
    if(event.type==='switch_connected')return `OpenFlow 1.3 connected; mitigation ${event.mitigation_enabled?'enabled':'disabled'}.`;
    if(event.event==='start')return `${event.pps} packets/s · ${event.duration_s}s · ${event.source_log}.`;
    if(event.event==='stop')return `${fmt(event.sent)} packets sent · ${event.source_log}.`;
    return JSON.stringify(event);
  }
  function renderJournal() {
    const events=currentRun().events.filter(event=>event.t_s<=state.clock).slice(-30);
    const key=`${state.mode}:${state.mitigation}:`+events.map(event=>`${event.t_s}:${event.type||event.event}`).join('|');
    if(key===state.lastJournal)return;state.lastJournal=key;
    $('journal-count').textContent=`${events.length} EVENTS`;
    if(!events.length){$('journal-events').innerHTML='<div class="journal-empty">Every decision has a reason.<br>Press play to see the story unfold.</div>';return;}
    $('journal-events').innerHTML=events.map(event=>{
      const kind=event.type||event.event||'event';
      const group=kind==='alert'?'alert':kind.includes('drop')&&!kind.includes('removed')?'drop':kind.includes('expir')||kind.includes('removed')?'expiry':'';
      const label=kind==='drop_confirmed'?(state.mode==='recorded'?'BARRIER REPLY':'MODELED DROP APPLIED'):(eventNames[kind]||kind.toUpperCase());
      return `<div class="event ${group}"><span class="event-time">${Number(event.t_s).toFixed(1)}s</span><div class="event-content"><strong>${esc(label)}</strong><p>${esc(eventMessage(event))}</p></div></div>`;
    }).join('');
    $('journal-events').scrollTop=$('journal-events').scrollHeight;
  }
  function drawChart() {
    const holder=$('comparison-chart');if(!holder||state.page!=='lab'||state.mode==='live'||!state.runs||!window.d3)return;
    const recorded=state.mode==='recorded';if(recorded&&!state.recorded)return;
    let off,on;
    if(recorded){
      const midpoints=key=>state.recorded.comparison[key].attacker_windows.map(row=>{
        const original=state.recorded.trials[key].victim_frames.find(window=>Math.abs(window.t_s-row.relative_s)<1e-8);
        return {x:row.relative_s+(original?original.elapsed_s:1)/2,y:row.pps};
      });
      off=midpoints('attack_off');on=midpoints('attack_on');
    }else{
      const points=run=>run.frames.map(frame=>({x:frame.t_s,y:Object.entries(frame.source_delivered_pps).filter(([ip])=>ip!==CLIENT).reduce((sum,[,rate])=>sum+(rate||0),0)}));
      off=points(state.runs.off);on=points(state.runs.on);
    }
    state.chartData=[off,on];
    const width=Math.max(280,holder.getBoundingClientRect().width),height=holder.getBoundingClientRect().height||190;
    const m={top:16,right:16,bottom:32,left:47};
    const maxX=recorded?8:state.max;
    const x=d3.scaleLinear().domain([0,maxX]).range([m.left,width-m.right]);
    const maxY=Math.max(100,d3.max([...off,...on],d=>d.y)||100)*1.15;
    const y=d3.scaleLinear().domain([0,maxY]).nice().range([height-m.bottom,m.top]);
    state.chartScales={x,y,width,height,m,maxX};
    holder.replaceChildren();
    const svg=d3.select(holder).append('svg').attr('viewBox',`0 0 ${width} ${height}`).attr('role','img').attr('aria-label',recorded?'Measured attacker packet receive rates from the two original trials':'Modeled attacker packet receive rates for the same offered traffic');
    y.ticks(3).forEach(tick=>{svg.append('line').attr('x1',m.left).attr('x2',width-m.right).attr('y1',y(tick)).attr('y2',y(tick)).attr('stroke','#d7cfc3').attr('stroke-width',.7);svg.append('text').attr('class','chart-label').attr('x',m.left-9).attr('y',y(tick)+3).attr('text-anchor','end').text(fmt(tick));});
    const ticks=width<500?[0,maxX/2,maxX]:recorded?[0,2,4,6,8]:d3.range(0,maxX+.001,maxX>30?10:5);
    ticks.forEach(tick=>svg.append('text').attr('class','chart-label').attr('x',x(tick)).attr('y',height-15).attr('text-anchor',tick===maxX?'end':tick===0?'start':'middle').text(`${tick}s`));
    svg.append('text').attr('class','chart-label').attr('x',m.left).attr('y',9).text('ATTACKER PACKETS / SECOND');
    const line=d3.line().x(d=>x(d.x)).y(d=>y(d.y)).curve(recorded?d3.curveLinear:d3.curveStepAfter);
    const area=d3.area().x(d=>x(d.x)).y0(y(0)).y1(d=>y(d.y)).curve(recorded?d3.curveLinear:d3.curveStepAfter);
    svg.append('path').datum(off).attr('d',area).attr('fill','#c35332').attr('opacity',.07);
    svg.append('path').datum(off).attr('d',line).attr('fill','none').attr('stroke','#c35332').attr('stroke-width',1.8).attr('stroke-dasharray','5 4');
    svg.append('path').datum(on).attr('d',line).attr('fill','none').attr('stroke','#557652').attr('stroke-width',2.4);
    if(recorded){
      for(const [rows,color] of [[off,'#c35332'],[on,'#557652']])svg.selectAll(null).data(rows).enter().append('circle').attr('cx',d=>x(d.x)).attr('cy',d=>y(d.y)).attr('r',2.5).attr('fill',color);
    }
    svg.append('line').attr('id','chart-cursor').attr('y1',m.top).attr('y2',height-m.bottom).attr('stroke','#573d55').attr('stroke-width',1).attr('opacity',.7);
    svg.append('circle').attr('id','chart-cursor-dot').attr('r',4).attr('fill','#573d55');
    svg.append('rect').attr('x',m.left).attr('y',m.top).attr('width',width-m.left-m.right).attr('height',height-m.top-m.bottom).attr('fill','transparent').attr('aria-hidden','true').on('pointermove',function(event){
      const px=d3.pointer(event,this)[0];const time=Math.max(0,Math.min(maxX,x.invert(px)));
      showChartTooltip(time);
    }).on('pointerleave',()=>holder.querySelector('.chart-tooltip')?.remove()).on('click',function(event){const time=x.invert(d3.pointer(event,this)[0]);setPlaying(false);state.clock=Math.max(0,Math.min(state.max,time));render(true);});
    $('comparison-title').textContent=recorded?'What the victim actually received.':'What makes it through?';
    $('comparison-caption').textContent=recorded?'Measured victim.jsonl windows; dots are window midpoints. Historical results: 80/80 legitimate replies in BOTH runs. These runs predate the current hardening.':'Both traces use the same modeled inputs. They show attacker traffic delivered by forwarding policy; capacity does not change these counter rates.';
    updateChartCursor();
  }
  function showChartTooltip(time) {
    const holder=$('comparison-chart');let tooltip=holder.querySelector('.chart-tooltip');
    if(!tooltip){tooltip=document.createElement('div');tooltip.className='chart-tooltip';holder.append(tooltip);}
    const nearest=rows=>rows.reduce((prev,row)=>Math.abs(row.x-time)<Math.abs(prev.x-time)?row:prev,rows[0]||{x:0,y:0});
    tooltip.innerHTML=`<strong>${time.toFixed(1)}s</strong> · nearest observations<br>Without: ${fmt(nearest(state.chartData[0]).y)} packets/s<br>With: ${fmt(nearest(state.chartData[1]).y)} packets/s`;
  }
  function updateChartCursor() {
    const scales=state.chartScales;if(!scales||!$('chart-cursor'))return;
    const time=Math.min(state.clock,scales.maxX);
    const rows=state.chartData[state.mitigation?1:0]||[];
    let point=rows[0]||{y:0};for(const row of rows){if(row.x>time)break;point=row;}
    $('chart-cursor').setAttribute('x1',scales.x(time));$('chart-cursor').setAttribute('x2',scales.x(time));
    $('chart-cursor-dot').setAttribute('cx',scales.x(time));$('chart-cursor-dot').setAttribute('cy',scales.y(point.y));
  }
  const pathDefs=[['client','10.0.0.11','#557652'],['a1','10.0.0.21','#c35332'],['a2','10.0.0.22','#c35332'],['a3',A3,'#c35332']];
  const particlePool=[];
  let lastParticleKey='';
  let particleGroup=null;
  function positionParticle(index,path,progress,color,radius,opacity=1) {
    let circle=particlePool[index];
    if(!circle){circle=document.createElementNS('http://www.w3.org/2000/svg','circle');particlePool[index]=circle;}
    if(circle.parentNode!==particleGroup)particleGroup.append(circle);
    const point=path.getPointAtLength(path.getTotalLength()*progress);
    circle.setAttribute('cx',point.x);circle.setAttribute('cy',point.y);circle.setAttribute('r',radius);circle.setAttribute('fill',color);circle.setAttribute('opacity',opacity);circle.removeAttribute('display');
  }
  function drawParticles() {
    if(state.page!=='lab'||state.mode==='live'||!state.runs||(state.mode==='recorded'&&!state.recorded))return;
    const frame=getFrame();if(!frame)return;let index=0;
    const mobile=matchMedia('(max-width:600px)').matches,prefix=mobile?'mobile-':'';
    particleGroup=$(prefix+'flow-particles');
    const key=`${mobile}:${state.mode}:${state.mitigation}:${state.scenario}:${state.clock.toFixed(2)}:${state.pps}`;
    if(key===lastParticleKey)return;lastParticleKey=key;
    const motion=state.reduced?8:state.clock;
    for(const [pathId,source,color] of pathDefs){
      const offered=frame.source_offered_pps[source]||0;
      const count=offered?Math.min(20,Math.max(2,Math.round(Math.log2(offered+1)*1.6))):0;
      const path=$(`${prefix}path-${pathId}`)||(pathId==='a3'?$(`${prefix}path-a2`):null);
      if(!path)continue;
      for(let i=0;i<count;i++)positionParticle(index++,path,(motion*.35+i/count)%1,color,source==='10.0.0.11'?2.7:2.3,.85);
    }
    const deliveredAttack=(frame.source_delivered_pps['10.0.0.21']||0)+(frame.source_delivered_pps['10.0.0.22']||0)+(frame.source_delivered_pps[A3]||0);
    const serverPath=$(prefix+'path-server');
    if(frame.victim_delivered_pps>0){
      const count=Math.min(22,Math.max(3,Math.round(Math.log2(frame.victim_delivered_pps+1)*1.6)));
      for(let i=0;i<count;i++)positionParticle(index++,serverPath,(motion*.5+i/count)%1,deliveredAttack>100&&i%3?'#c35332':'#557652',2.5,.85);
    }
    if(state.clock>0){const control=$(prefix+'path-control');for(let i=0;i<2;i++)positionParticle(index++,control,(motion*.65+i*.5)%1,'#573d55',2,.65);}
    for(let i=index;i<particlePool.length;i++)particlePool[i].setAttribute('display','none');
  }
  function updateTopology(reset=false) {
    const active=!reset&&state.mode==='simulation'&&!!state.runs&&A3 in (state.runs.on.frames[0]?.source_offered_pps||{});
    const host=$('host-a3');
    host.classList.toggle('dormant-host',!active);host.classList.toggle('attacker-host',active);
    $('path-a3').classList.toggle('dormant-wire',!active);$('path-a3').classList.toggle('attack-wire',active);
    $('name-a3').textContent=active?'Traffic source C':'Source C · reserve';
    host.setAttribute('aria-label',active?'Explain traffic source three':'Explain the reserve source');
    if(!active)$('rate-a3').textContent='';
    $('mobile-sources-name').textContent=active?'Sources A + B + C':'Sources A + B';
    $('mobile-sources-address').textContent=active?'.21 / .22 / .23':'.21 / .22 · C in reserve';
  }
  let originalPolicyNote=null;
  function restorePolicyNote() {if(originalPolicyNote!==null)document.querySelector('.policy-note').innerHTML=originalPolicyNote;}
  function updatePolicyNote() {
    const note=document.querySelector('.policy-note');if(originalPolicyNote===null)originalPolicyNote=note.innerHTML;
    const run=state.runs?.on;if(!run)return;
    const params=run.parameters,p=run.detector_parameters||{},th=run.thresholds;
    if(params.detector==='threshold'&&params.action==='drop'&&!params.backoff){restorePolicyNote();return;}
    const rule={
      threshold:`<strong>&gt;${fmt(th.victim_pps)}</strong> victim packets/s + <strong>${fmt(th.min_sources)} sources</strong> above ${fmt(th.source_pps)} packets/s, for <strong>${fmt(th.consecutive_windows)} consecutive windows.</strong>`,
      ewma:`A source above its learned mean + <strong>${fmt(p.k_sigma,1)}σ</strong> (and over ${fmt(p.min_rate_pps)} packets/s) while the victim total is also anomalous, for <strong>${fmt(th.consecutive_windows)} consecutive windows.</strong>`,
      cusum:`A source’s running sum of standardised excess rate exceeds <strong>h = ${fmt(p.threshold_h,1)}</strong> (drift ${fmt(p.drift_k,1)}). Pulses accumulate across quiet seconds.`,
      entropy:`Traffic-mix divergence above <strong>${fmt(p.kl_threshold_bits,2)} bits</strong> with a victim surge; offenders’ shares rose by over ${fmt(p.share_delta*100)}%, for <strong>${fmt(th.consecutive_windows)} windows.</strong>`
    }[params.detector];
    const action=params.action==='drop'?'DROP':params.action==='rate_limit'?`RATE-LIMIT ${fmt(params.rate_limit_pps)} PPS`:`RATE-LIMIT ${fmt(params.rate_limit_pps)} PPS, THEN DROP`;
    note.innerHTML=`<span class="eyebrow">THE DETECTION RULE · ${esc(detectorInfo[params.detector][1].toUpperCase())}</span><p>${rule}</p><span class="mono">ACTION: ${action} · SOURCE → VICTIM UDP :9000<br>LIFETIME: ${fmt(th.mitigation_hard_timeout_s)} SECONDS${params.backoff?', DOUBLING FOR REPEAT OFFENSES':''}</span>`;
  }
  async function loadBenchmark() {
    if(state.benchmark)return;
    try{
      const data=await api('/api/benchmark');state.benchmark=data;
      const bench=data.benchmark,detectors=bench.detectors,results=bench.results;
      const order=(state.bootstrap?.scenarios||[]).map(item=>item.id).filter(id=>id in results[detectors[0]]);
      for(const id of Object.keys(results[detectors[0]]))if(!order.includes(id))order.push(id);
      $('benchmark-head').innerHTML=`<tr><th scope="col">Scenario</th>${detectors.map(name=>`<th scope="col">${esc(detectorInfo[name]?.[0]||name)}</th>`).join('')}</tr>`;
      $('benchmark-rows').innerHTML=order.map(id=>{
        const benign=results[detectors[0]][id].benign;
        const cells=detectors.map(name=>{
          const row=results[name][id];
          if(benign)return `<td class="${row.false_positive_runs?'bad':'good'}">FP ${fmt(row.false_positive_runs)}/${fmt(row.runs)}</td>`;
          const rate=row.detection_rate||0,latency=row.median_latency_s;
          return `<td class="${rate>=.9?'good':rate<.5?'bad':'mid'}">${fmt(rate*100)}%${latency==null?'':` · ${fmt(latency,1)} s`}</td>`;
        }).join('');
        const label=(state.bootstrap?.scenarios||[]).find(item=>item.id===id)?.label||bench.scenarios[id]?.label||id;
        return `<tr class="${benign&&!/benign/i.test(label)?'benign-row':''}"><th scope="row">${esc(label)}</th>${cells}</tr>`;
      }).join('');
      const params=bench.parameters||{};
      $('benchmark-note').textContent=`${data.provenance.label} ${fmt(params.seeds)} seeded runs per cell (seed base ${fmt(params.seed_base)}), ${fmt(params.pps_per_attacker)} packets/s per attacker, Poisson noise on every source. ${data.provenance.warning}`;
    }catch(error){$('benchmark-rows').innerHTML=`<tr><td class="packet-empty">The offline benchmark is unavailable: ${esc(error.message)}</td></tr>`;}
  }
  async function runProbe() {
    const button=$('run-probe');button.disabled=true;button.textContent='Sending five local requests…';$('live-csv').hidden=true;
    $('live-result').textContent='Starting the real echo service on 127.0.0.1. Waiting for five replies…';
    try{
      const data=await api('/api/probe',{method:'POST',headers:{'Content-Type':'application/json','X-FlowGuard-CSRF':state.bootstrap.csrf_token},body:'{}'});
      const s=data.summary;
      $('live-result').innerHTML=`<strong>${s.received} / ${s.sent} real replies received.</strong> Loss: ${s.loss_percent.toFixed(0)}%. Mean round-trip time: ${s.mean_rtt_ms===null?'unavailable':s.mean_rtt_ms.toFixed(3)+' ms'}.<br>Actual localhost measurements. The echo service has stopped automatically.`;
      $('live-csv').textContent=data.csv;$('live-csv').hidden=false;
    }catch(error){$('live-result').textContent=`The local check could not finish: ${error.message}. Retry after checking the Python server terminal.`;}
    finally{button.disabled=false;button.textContent='Run another UDP check ↗';}
  }
  function populateIncident() {
    $('incident-title').innerHTML='One small request.<br>A very <em>large reply.</em>';
    $('incident-meta').innerHTML='GITHUB.COM<br>28 FEBRUARY 2018<br>MEMCACHED / UDP REFLECTION';
    $('incident-article').innerHTML=`<p>On 28 February 2018, GitHub faced a memcached reflection flood. GitHub reported a peak of <strong>1.35 terabits per second</strong> and <strong>126.9 million packets per second</strong>. <a href="https://github.blog/news-insights/company-news/ddos-incident-report/" target="_blank" rel="noopener">Incident report ↗</a></p><div class="case-magnitude"><div><strong>1.35 <small>Tbps</small></strong><span>REPORTED PEAK THROUGHPUT</span></div><div><strong>126.9 <small>Mpps</small></strong><span>REPORTED PEAK PACKET RATE</span></div></div><h2>Borrow an address. Multiply a reply.</h2><p>An initiator forged the victim’s source IP in small UDP requests sent to exposed memcached servers. Those third-party servers replied toward the victim, multiplying the traffic. Cloudflare’s technical account identifies UDP port 11211. The apparent senders at the victim are <strong>reflectors</strong>, not necessarily the initiator. <a href="https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/" target="_blank" rel="noopener">How reflection works ↗</a></p><div class="reflection-path"><strong>Initiator</strong><span>→</span><strong>Exposed reflectors</strong><span>⇒</span><strong>GitHub</strong></div><h2>Move the filtering upstream.</h2><p>GitHub began rerouting toward Akamai at 17:26 UTC. The provider’s border ACLs filtered the flood; GitHub reported full recovery at 17:30. Local filtering alone cannot restore a link that the upstream flood has already saturated. <a href="https://github.blog/news-insights/company-news/ddos-incident-report/" target="_blank" rel="noopener">Response timeline ↗</a></p>`;
    $('incident-connection').textContent='Both stories highlight measuring traffic and enforcing filters. GitHub detected an unusual traffic ratio and used upstream mitigation. FlowGuard demonstrates a separate, simple two-window detector and local switch policy in a fixed five-host UDP echo lab.';
    $('incident-boundary').textContent='The dashboard’s lab model is a direct UDP flood, not a reconstruction of the GitHub incident. It does not implement memcached reflection, Internet routing, or upstream scrubbing. The reported incident peak is a sourced fact; no synthetic curve is presented as GitHub’s telemetry.';
    $('incident-sources').innerHTML='<a href="https://github.blog/news-insights/company-news/ddos-incident-report/" target="_blank" rel="noopener">GitHub · First-party incident report ↗</a><a href="https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/" target="_blank" rel="noopener">Cloudflare · Memcached reflection explained ↗</a><a href="https://www.rfc-editor.org/rfc/rfc2827.html" target="_blank" rel="noopener">IETF BCP 38 · Source-address filtering ↗</a>';
    const response=document.createElement('section');response.className='incident-response';
    response.innerHTML='<span class="eyebrow">STEP THROUGH THE PUBLISHED RESPONSE · UTC</span><div class="incident-steps"><button class="active" data-incident-step="0"><strong>17:21</strong><span>Detect</span></button><button data-incident-step="1"><strong>17:26</strong><span>Reroute</span></button><button data-incident-step="2"><strong>17:30</strong><span>Recover</span></button></div><p id="incident-response-copy" aria-live="polite">GitHub detected an unusual incoming-to-outgoing traffic ratio. Monitoring identified the flood; an alert alone could not restore the saturated edge.</p><small>Published milestone times, not a reconstruction of the attack’s packet timeline. <a href="https://github.blog/news-insights/company-news/ddos-incident-report/" target="_blank" rel="noopener">GitHub’s account ↗</a></small>';
    $('incident-article').append(response);
    const responseCopy=[
      'GitHub detected an unusual incoming-to-outgoing traffic ratio. Monitoring identified the flood; an alert alone could not restore the saturated edge.',
      'GitHub began shifting routing toward Akamai. The mitigation provider supplied upstream capacity and border filtering beyond a local application’s reach.',
      'GitHub reported full recovery by 17:30 UTC after routing converged and border ACLs mitigated the flood. Detection, enforcement, and recovery are separate milestones.'
    ];
    response.querySelectorAll('[data-incident-step]').forEach(button=>button.addEventListener('click',()=>{response.querySelectorAll('button').forEach(el=>el.classList.toggle('active',el===button));$('incident-response-copy').textContent=responseCopy[Number(button.dataset.incidentStep)];}));
  }
  function setupEvents() {
    document.querySelector('.brand').addEventListener('click',event=>{event.preventDefault();navigate('lab');});
    $$('.nav-item').forEach(el=>el.addEventListener('click',()=>navigate(el.dataset.page)));
    $$('.mode-tab').forEach(el=>el.addEventListener('click',()=>setMode(el.dataset.mode)));
    $('scenario').addEventListener('change',()=>{state.scenario=$('scenario').value;setPlaying(false);loadSimulation(true);});
    $$('[data-story]').forEach(button=>button.addEventListener('click',()=>chooseStory(button.dataset.story)));
    $('notes-toggle').addEventListener('click',()=>toggleNotes(!state.notesOpen));
    $('notes-close').addEventListener('click',()=>{toggleNotes(false);$('notes-toggle').focus();});
    $('try-cusum').addEventListener('click',()=>{state.detector=state.detector==='cusum'?'threshold':'cusum';$('detector').value=state.detector;$('detector-caption').textContent=detectorInfo[state.detector][2];setPlaying(false);loadSimulation(true);});
    $$('[data-note]').forEach(button=>{button.addEventListener('click',()=>selectNote(button.dataset.note));button.addEventListener('keydown',event=>{const tabs=$$('[data-note]');let i=tabs.indexOf(button);if(event.key==='ArrowRight')i=(i+1)%tabs.length;else if(event.key==='ArrowLeft')i=(i+tabs.length-1)%tabs.length;else if(event.key==='Home')i=0;else if(event.key==='End')i=tabs.length-1;else return;event.preventDefault();selectNote(tabs[i].dataset.note);tabs[i].focus();});});
    $('mitigation').addEventListener('click',()=>{state.mitigation=!state.mitigation;$('mitigation').classList.toggle('on',state.mitigation);$('mitigation').setAttribute('aria-checked',String(state.mitigation));$('mitigation-state').textContent=state.mitigation?'ON':'OFF';$('mitigation-caption').textContent=state.mitigation?'Detect, then block the offenders':'Observe and alert; keep forwarding';state.lastJournal='';render(true);toast(`Replaying the same inputs with mitigation ${state.mitigation?'ON':'OFF'}.`);});
    $('compare-toggle').addEventListener('click',()=>{state.compare=!state.compare;$('compare-region').hidden=!state.compare;$('compare-toggle').setAttribute('aria-pressed',String(state.compare));if(state.compare){toggleNotes(false);drawChart();}});
    $('compare-close').addEventListener('click',()=>{closeComparison();$('compare-toggle').focus();});
    $('settings-toggle').addEventListener('click',()=>{const open=$('settings').hidden;$('settings').hidden=!open;$('settings-toggle').setAttribute('aria-expanded',String(open));});
    $('why-toggle').addEventListener('click',()=>{const open=$('moment-detail').hidden;$('moment-detail').hidden=!open;$('why-toggle').setAttribute('aria-expanded',String(open));});
    for(const [id,key] of [['pps','pps'],['capacity','capacity'],['rate-limit','rateLimit'],['queue-size','queueSize']]){
      const output=id==='rate-limit'?'rate-limit-value':id==='queue-size'?'queue-value':`${id}-value`;
      $(id).addEventListener('input',()=>{$(output).textContent=fmt($(id).value);});
      $(id).addEventListener('change',()=>{state[key]=Number($(id).value);setPlaying(false);loadSimulation(false);});
    }
    $('detector').addEventListener('change',()=>{state.detector=$('detector').value;$('detector-caption').textContent=detectorInfo[state.detector][2];setPlaying(false);loadSimulation(false);toast(`Replaying with the ${detectorInfo[state.detector][1]}.`);});
    $('action').addEventListener('change',()=>{state.action=$('action').value;$('action-caption').textContent=actionCaptions[state.action];$('rate-limit').disabled=state.action==='drop';setPlaying(false);loadSimulation(false);});
    $('backoff').addEventListener('change',()=>{state.backoff=$('backoff').checked;setPlaying(false);loadSimulation(false);});
    $('queue-toggle').addEventListener('change',()=>{state.queueOn=$('queue-toggle').checked;$('queue-size').disabled=!state.queueOn;setPlaying(false);loadSimulation(false);});
    $('play').addEventListener('click',()=>{if(state.clock>=state.max)state.clock=0;setPlaying(!state.playing);});
    $('restart').addEventListener('click',()=>{state.clock=0;setPlaying(false);state.lastJournal='';render(true);});
    $('timeline').addEventListener('input',()=>{setPlaying(false);state.clock=Number($('timeline').value);render(true);});
    $('speed').addEventListener('click',()=>{state.speed=state.speed===1?2:state.speed===2?.5:1;$('speed').textContent=`${state.speed}×`;});
    $('run-probe').addEventListener('click',runProbe);
    $('incident-replay').addEventListener('click',()=>{navigate('lab');state.scenario='sustained';$('scenario').value='sustained';setMode('simulation');});
    $$('.protocol').forEach(el=>el.addEventListener('click',()=>{$$('.protocol').forEach(button=>button.classList.toggle('active',button===el));$('protocol-explanation').innerHTML=protocolCopy[el.dataset.protocol];}));
    $('protocol-explanation').innerHTML=protocolCopy.udp;
    for(const [button,dialog] of [['guide-open','guide-dialog'],['credits-open','credits-dialog']])$(button).addEventListener('click',()=>{$(dialog).showModal();setPlaying(false);});
    $$('.dialog-close').forEach(el=>el.addEventListener('click',()=>el.closest('dialog').close()));
    $$('dialog').forEach(dialog=>dialog.addEventListener('click',event=>{if(event.target===dialog){const r=dialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)dialog.close();}}));
    $$('[data-explain]').forEach(el=>{
      const open=()=>{const copy=explain[el.dataset.explain];$('node-tooltip').querySelector('strong').textContent=copy[0];$('node-tooltip').querySelector('p').textContent=copy[1];$('node-tooltip').hidden=false;};
      el.addEventListener('click',open);el.addEventListener('keydown',event=>{if(event.key==='Enter')open();});
    });
    $('node-tooltip-close').addEventListener('click',()=>$('node-tooltip').hidden=true);
    const fullscreen=()=>{if(!document.fullscreenElement)document.documentElement.requestFullscreen?.().catch(()=>toast('Use your browser’s full-screen command.'));else document.exitFullscreen?.();};
    $('present').addEventListener('click',fullscreen);
    document.addEventListener('fullscreenchange',()=>{document.body.classList.toggle('presentation-mode',!!document.fullscreenElement);$('present').setAttribute('aria-label',document.fullscreenElement?'Exit full screen':'Enter full screen');drawChart();});
    document.addEventListener('keydown',event=>{
      if(event.key==='Escape'){if(!$('settings').hidden){$('settings').hidden=true;$('settings-toggle').setAttribute('aria-expanded','false');}if(!$('moment-detail').hidden){$('moment-detail').hidden=true;$('why-toggle').setAttribute('aria-expanded','false');}if(state.notesOpen){toggleNotes(false);$('notes-toggle').focus();}if(state.compare){closeComparison();$('compare-toggle').focus();}}
      if((event.key==='n'||event.key==='N')&&!event.target.matches('input,select,textarea')&&!document.querySelector('dialog[open]')&&state.page==='lab'&&state.mode!=='live'){event.preventDefault();toggleNotes(!state.notesOpen);}
      if(event.target.matches('input,select,textarea,button,a')||document.querySelector('dialog[open]'))return;
      if(event.key==='f'||event.key==='F'){event.preventDefault();fullscreen();}
      if(state.page==='lab'&&state.mode!=='live'){
        if(event.code==='Space'){event.preventDefault();if(state.clock>=state.max)state.clock=0;setPlaying(!state.playing);}
        if(event.key==='ArrowLeft'||event.key==='ArrowRight'){event.preventDefault();setPlaying(false);state.clock=Math.max(0,Math.min(state.max,state.clock+(event.key==='ArrowRight'?1:-1)));render(true);}
      }
    });
    new ResizeObserver(()=>drawChart()).observe($('comparison-chart'));
  }
  let previousTime=0;
  function loop(now) {
    const elapsed=previousTime?Math.min((now-previousTime)/1000,.2):0;previousTime=now;
    if(state.playing){state.clock=Math.min(state.max,state.clock+elapsed*state.speed);if(state.clock>=state.max)setPlaying(false);render();}
    drawParticles();requestAnimationFrame(loop);
  }
  function applyDefaults(defaults) {
    if(defaults.detector in detectorInfo){state.detector=defaults.detector;$('detector').value=state.detector;$('detector-caption').textContent=detectorInfo[state.detector][2];}
    if(defaults.action in actionCaptions){state.action=defaults.action;$('action').value=state.action;$('action-caption').textContent=actionCaptions[state.action];}
    $('rate-limit').disabled=state.action==='drop';
    state.backoff=!!defaults.backoff;$('backoff').checked=state.backoff;
    if(Number.isFinite(defaults.rate_limit_pps)){state.rateLimit=Math.min(200,Math.max(5,defaults.rate_limit_pps));$('rate-limit').value=state.rateLimit;$('rate-limit-value').textContent=fmt(state.rateLimit);}
    const queue=state.bootstrap.queue_defaults||{};
    if(Number.isFinite(queue.queue_packets)){state.queueSize=queue.queue_packets;$('queue-size').value=state.queueSize;$('queue-value').textContent=fmt(state.queueSize);}
  }
  async function boot() {
    setupEvents();populateIncident();selectNote('controller');
    try{state.bootstrap=await api('/api/bootstrap');applyDefaults(state.bootstrap.simulation_defaults||{});await chooseStory('burst');}
    catch(error){toast(`Start the local Python server: ${error.message}`);$('chapter-title').textContent='The local service needs attention.';$('chapter-copy').textContent='Run python demo/server.py in the project, then reload this page.';}
    const hash=location.hash.slice(1);if(['incident','learn'].includes(hash))navigate(hash);
    requestAnimationFrame(loop);
  }
  boot();
})();
