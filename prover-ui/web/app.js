(() => {
  "use strict";

  const state = {
    campaigns: [],
    selectedCampaignId: "ark-cashu-live",
    activeTab: "live",
    live: null,
    polling: true,
    eventSource: null,
    fallbackTimer: null,
    correlateTimer: null,
    // Liveness & animation state
    lastSeenSeq: null,
    lastSamplePerfMs: performance.now(),
    basePhaseElapsedS: 0,
    baseCooldownRemS: 0,
    baseTaskElapsedS: 0,
    opMode: "proving_inflight",
    busParticles: [],
    busRings: [],
    tileBursts: [],
    mosaicRects: [],
    hoveredTile: null,
    replayingPreview: false,
    replayTimers: [],
    highlightedSeqs: new Set(),
  };

  const PRESETS = {
    m16_mainnet: {
      header_blocks: 975072,
      nova_header_shards: 2,
      utxo_window_blocks: 0,
      payment_utxos: 1,
      shinigami_leaves: 0,
      ark_vtxos: 0,
      shinigami_script_type: "p2wpkh",
      element_threshold_exp: 27,
      hardware_profile: "rtx5080_12gib",
    },
    m18_window: {
      header_blocks: 975072,
      nova_header_shards: 2,
      utxo_window_blocks: 6,
      payment_utxos: 1,
      shinigami_leaves: 0,
      ark_vtxos: 0,
      shinigami_script_type: "p2wpkh",
      element_threshold_exp: 27,
      hardware_profile: "rtx5080_12gib",
    },
    ark_live: {
      header_blocks: 0,
      nova_header_shards: 0,
      utxo_window_blocks: 0,
      payment_utxos: 0,
      shinigami_leaves: 0,
      ark_vtxos: 4,
      shinigami_script_type: "p2wpkh",
      element_threshold_exp: 26,
      hardware_profile: "rtx5080_bounded_2gib",
    },
    ark_round_128: {
      header_blocks: 1016,
      nova_header_shards: 1,
      utxo_window_blocks: 0,
      payment_utxos: 4,
      shinigami_leaves: 16,
      ark_vtxos: 128,
      shinigami_script_type: "taproot_vtxo_exit",
      element_threshold_exp: 26,
      hardware_profile: "rtx5080_bounded_2gib",
    },
    shinigami_batch: {
      header_blocks: 0,
      nova_header_shards: 0,
      utxo_window_blocks: 0,
      payment_utxos: 8,
      shinigami_leaves: 64,
      ark_vtxos: 0,
      shinigami_script_type: "p2sh_multisig",
      element_threshold_exp: 27,
      hardware_profile: "rtx5080_12gib",
    },
  };

  const $ = (id) => document.getElementById(id);

  function fmtInt(n) {
    if (n === null || n === undefined || Number.isNaN(Number(n))) return "--";
    return Number(n).toLocaleString("en-US");
  }

  function fmtGiB(bytes, digits = 2) {
    if (bytes === null || bytes === undefined) return "--";
    return (Number(bytes) / 1073741824).toFixed(digits);
  }

  function fmtAgo(unixSec) {
    if (!unixSec) return "--";
    const diff = Math.max(0, Math.round(Date.now() / 1000 - unixSec));
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s ago`;
    return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m ago`;
  }

  function shortHex(h, head = 10, tail = 6) {
    if (!h || typeof h !== "string") return "--";
    if (h.length <= head + tail + 2) return h;
    return `${h.slice(0, head)}…${h.slice(-tail)}`;
  }

  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function getCampaign(id) {
    return state.campaigns.find((c) => c.id === id) || state.campaigns[0] || null;
  }

  // --- Controls & Replay ---
  function initControls() {
    document.querySelectorAll(".nav-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const tab = btn.dataset.tab;
        state.activeTab = tab;
        document.querySelectorAll(".nav-btn").forEach((b) => {
          const active = b.dataset.tab === tab;
          b.classList.toggle("active", active);
          b.setAttribute("aria-selected", active ? "true" : "false");
        });
        document.querySelectorAll(".tab-panel").forEach((p) => {
          p.hidden = p.id !== `tab-${tab}`;
        });
      });
    });

    $("toggle-theme").addEventListener("click", () => {
      const html = document.documentElement;
      const next = html.getAttribute("data-theme") === "grove" ? "dark" : "grove";
      html.setAttribute("data-theme", next);
      $("toggle-theme").textContent = next === "grove" ? "Dark Theme" : "Grove Theme";
    });

    $("toggle-poll").addEventListener("click", () => {
      state.polling = !state.polling;
      $("toggle-poll").textContent = state.polling ? "Pause Poll" : "Resume Poll";
      $("poll-label").textContent = state.polling
        ? "Live 1s SSE stream active"
        : "Telemetry stream paused";
      $("live-dot").classList.toggle("live", state.polling);
      if (state.polling) {
        connectStream();
      } else if (state.eventSource) {
        state.eventSource.close();
        state.eventSource = null;
      }
    });

    const replayBtn = $("replay-completions-btn");
    if (replayBtn) {
      replayBtn.addEventListener("click", triggerRecentReplay);
    }

    const canvas = $("shard-mosaic-canvas");
    if (canvas) {
      canvas.addEventListener("mousemove", (ev) => {
        const rect = canvas.getBoundingClientRect();
        const x = ((ev.clientX - rect.left) / rect.width) * canvas.width;
        const y = ((ev.clientY - rect.top) / rect.height) * canvas.height;
        let hit = null;
        for (const tile of state.mosaicRects) {
          if (x >= tile.x && x <= tile.x + tile.w && y >= tile.y && y <= tile.y + tile.h) {
            hit = tile;
            break;
          }
        }
        state.hoveredTile = hit;
        if (hit) {
          $("mosaic-hover-label").textContent = hit.inFlight
            ? `IN-FLIGHT SLOT · Active ${state.opMode} worker`
            : `${hit.kind === 1 ? "RecursionReduce" : "ProveShard"} · key ${hit.key} · ${hit.sec}s · ${
                hit.replayed ? "MEMO REPLAY" : "CUDA PROVED"
              }`;
        } else {
          $("mosaic-hover-label").textContent =
            "Hover any tile to inspect task digest & proving latency · Leading slot pulses while proving";
        }
      });
      canvas.addEventListener("mouseleave", () => {
        state.hoveredTile = null;
      });
    }

    const sliderPairs = [
      ["est-header-blocks", "out-header-blocks"],
      ["est-header-shards", "out-header-shards"],
      ["est-window-blocks", "out-window-blocks"],
      ["est-payment-utxos", "out-payment-utxos"],
      ["est-shinigami-leaves", "out-shinigami-leaves"],
      ["est-ark-vtxos", "out-ark-vtxos"],
    ];
    sliderPairs.forEach(([inId, outId]) => {
      const el = $(inId);
      el.addEventListener("input", () => {
        $(outId).textContent = fmtInt(el.value);
        clearActivePreset();
        scheduleCorrelate();
      });
    });
    ["est-script-type", "est-threshold", "est-hw-profile"].forEach((id) => {
      $(id).addEventListener("change", () => {
        clearActivePreset();
        scheduleCorrelate();
      });
    });

    document.querySelectorAll(".preset-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = PRESETS[btn.dataset.preset];
        if (!p) return;
        document.querySelectorAll(".preset-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        applyPreset(p);
      });
    });
  }

  function clearActivePreset() {
    document.querySelectorAll(".preset-btn").forEach((b) => b.classList.remove("active"));
  }

  function applyPreset(p) {
    $("est-header-blocks").value = p.header_blocks;
    $("out-header-blocks").textContent = fmtInt(p.header_blocks);
    $("est-header-shards").value = p.nova_header_shards;
    $("out-header-shards").textContent = fmtInt(p.nova_header_shards);
    $("est-window-blocks").value = p.utxo_window_blocks;
    $("out-window-blocks").textContent = fmtInt(p.utxo_window_blocks);
    $("est-payment-utxos").value = p.payment_utxos;
    $("out-payment-utxos").textContent = fmtInt(p.payment_utxos);
    $("est-shinigami-leaves").value = p.shinigami_leaves;
    $("out-shinigami-leaves").textContent = fmtInt(p.shinigami_leaves);
    $("est-ark-vtxos").value = p.ark_vtxos;
    $("out-ark-vtxos").textContent = fmtInt(p.ark_vtxos);
    $("est-script-type").value = p.shinigami_script_type;
    $("est-threshold").value = String(p.element_threshold_exp);
    $("est-hw-profile").value = p.hardware_profile;
    runCorrelate();
  }

  // --- Shard Completion Burst Choreography ---
  function emitShardCompletionVisual(ev, tileIdxOverride = null, isReplayPreview = false) {
    const isReduce = ev.kind === "reduce";
    const sec = ((ev.ms || 0) / 1000).toFixed(1);
    const label = isReduce
      ? `+1 REDUCE · ${sec}s`
      : ev.replayed
      ? `↻ SHARD REPLAY`
      : `+1 SHARD · ${sec}s`;

    // 1. Flash Ribbon Card #4 & matching KPI Card
    const targets = [$("ribbon-shard-card")];
    if (state.selectedCampaignId === "ark-cashu-live") {
      targets.push(isReduce ? $("kpi-rec-card") : $("kpi-core-card"));
    }
    const cls = isReduce ? "flash-reduce" : "flash-shard";
    targets.forEach((card) => {
      if (!card) return;
      card.classList.remove("flash-shard", "flash-reduce");
      void card.offsetWidth;
      card.classList.add(cls);

      const toast = document.createElement("span");
      toast.className = `pop-toast ${isReduce ? "reduce" : "shard"}`;
      toast.textContent = isReplayPreview ? `▶ ${label}` : label;
      card.appendChild(toast);
      setTimeout(() => toast.remove(), 1950);
    });

    // 2. Launch high-energy comet particle along the Proof Bus SVG
    // EXEC (205) -> SHARD (340) for shard; SHARD (340) -> 3:1 REDUCE (475) for reduce
    const fromX = isReduce ? 340 : 205;
    const toX = isReduce ? 475 : 340;
    const color = isReduce ? "#a78bfa" : "#34d399";
    state.busParticles.push({
      fromX,
      toX,
      y: 38,
      progress: 0,
      speed: 0.032,
      r: 5.5,
      color,
      burstOnArrive: true,
    });

    // 3. Ignite corresponding tile in the Mosaic Canvas
    const tail = (((state.live || {}).wsl_prover || {}).progress || {}).mosaic_tail || [];
    const targetIdx =
      tileIdxOverride !== null ? tileIdxOverride : Math.max(0, tail.length - 1);
    state.tileBursts.push({
      idx: targetIdx,
      born: performance.now(),
      duration: 1350,
      color,
    });

    // 4. Mark feed item for slide-in highlight
    if (ev.seq) {
      state.highlightedSeqs.add(ev.seq);
      setTimeout(() => state.highlightedSeqs.delete(ev.seq), 2200);
    }
  }

  function triggerRecentReplay() {
    const wsl = (state.live && state.live.wsl_prover) || {};
    const events = ((wsl.progress || {}).recent_events || []).slice(-12);
    if (!events.length) return;

    state.replayTimers.forEach(clearTimeout);
    state.replayTimers = [];
    state.replayingPreview = true;
    $("replay-mode-pill").hidden = false;
    $("replay-completions-btn").textContent = "⚡ Replaying 12 Shards…";

    const tailLen = (((wsl.progress || {}).mosaic_tail) || []).length;
    events.forEach((ev, i) => {
      const tid = setTimeout(() => {
        const tileIdx = Math.max(0, tailLen - events.length + i);
        emitShardCompletionVisual(ev, tileIdx, true);
        renderCompletionFeed((wsl.progress || {}).recent_events || []);
      }, i * 380);
      state.replayTimers.push(tid);
    });

    const endTid = setTimeout(() => {
      state.replayingPreview = false;
      $("replay-mode-pill").hidden = true;
      $("replay-completions-btn").textContent = "▶ Replay Last 12 Shards";
    }, events.length * 380 + 900);
    state.replayTimers.push(endTid);
  }

  // --- 60fps Continuous Animation Loop (Stopwatch, Radial Ring, Bus, Mosaic) ---
  function startAnimationLoop() {
    let lastAmbientSpawn = 0;

    function frame(nowMs) {
      const dtSec = Math.max(0, (nowMs - state.lastSamplePerfMs) / 1000);
      updateCockpitTick(dtSec, nowMs);
      updateProofBusParticles(nowMs, lastAmbientSpawn, (ts) => {
        lastAmbientSpawn = ts;
      });
      drawShardMosaic(nowMs);
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  function updateCockpitTick(dtSec, nowMs) {
    const ringArc = $("cockpit-ring-arc");
    const orbit = $("cockpit-ring-orbit");
    const timerVal = $("cockpit-timer-val");
    if (!ringArc || !timerVal || !state.live) return;

    const wsl = state.live.wsl_prover || {};
    const lv = wsl.liveness || {};
    const mode = lv.mode || "proving_inflight";
    const circumference = 219.9;
    let frac = 0.25;
    let angleRad = (nowMs / 900) % (Math.PI * 2);

    if (mode === "cooldown_backoff") {
      const rem = Math.max(0, state.baseCooldownRemS - dtSec);
      timerVal.textContent = `${rem.toFixed(1)}s`;
      $("cockpit-timer-sub").textContent = "BACKOFF";
      frac = 1 - rem / 60.0;
      ringArc.setAttribute("stroke", "var(--amber)");
    } else if (mode === "waiting_headroom") {
      const waitS = state.basePhaseElapsedS + dtSec;
      timerVal.textContent = `${Math.floor(waitS)}s`;
      $("cockpit-timer-sub").textContent = "HEADROOM";
      frac = Math.min(1, (lv.headroom_pct || 0) / 100);
      ringArc.setAttribute("stroke", "var(--amber)");
      angleRad = (nowMs / 1400) % (Math.PI * 2);
    } else if (mode === "cuda_init") {
      const el = state.basePhaseElapsedS + dtSec;
      timerVal.textContent = `${el.toFixed(1)}s`;
      $("cockpit-timer-sub").textContent = "CUDA INIT";
      frac = Math.min(0.95, el / 95.0);
      ringArc.setAttribute("stroke", "var(--cyan)");
      angleRad = (nowMs / 550) % (Math.PI * 2);
    } else if (mode === "replaying_memo") {
      const el = state.basePhaseElapsedS + dtSec;
      timerVal.textContent = `${el.toFixed(1)}s`;
      $("cockpit-timer-sub").textContent = "REPLAY";
      frac = ((nowMs / 1200) % 1);
      ringArc.setAttribute("stroke", "var(--accent)");
      angleRad = (nowMs / 320) % (Math.PI * 2);
    } else if (mode === "completed") {
      timerVal.textContent = "DONE";
      $("cockpit-timer-sub").textContent = "VERIFIED";
      frac = 1;
      ringArc.setAttribute("stroke", "var(--accent)");
    } else {
      // proving_inflight
      const curS = state.baseTaskElapsedS + dtSec;
      const expS = Math.max(30, lv.expected_task_s || 300);
      timerVal.textContent = `${curS.toFixed(1)}s`;
      $("cockpit-timer-sub").textContent = "IN-FLIGHT";
      frac = Math.min(0.98, curS / expS);
      ringArc.setAttribute("stroke", "var(--cyan)");
      angleRad = (nowMs / 650) % (Math.PI * 2);
    }

    ringArc.setAttribute("stroke-dashoffset", (circumference * (1 - frac)).toFixed(1));
    if (orbit) {
      const ox = 42 + 35 * Math.cos(angleRad);
      const oy = 42 + 35 * Math.sin(angleRad);
      orbit.setAttribute("cx", ox.toFixed(1));
      orbit.setAttribute("cy", oy.toFixed(1));
    }
  }

  function updateProofBusParticles(nowMs, lastSpawn, setLastSpawn) {
    const layer = $("bus-particles-layer");
    if (!layer) return;

    const isRunning =
      state.opMode === "proving_inflight" ||
      state.opMode === "replaying_memo" ||
      state.opMode === "cuda_init" ||
      state.replayingPreview;

    const spawnEvery = state.opMode === "replaying_memo" ? 280 : isRunning ? 750 : 1800;
    if (nowMs - lastSpawn > spawnEvery) {
      setLastSpawn(nowMs);
      if (isRunning) {
        state.busParticles.push({
          fromX: 70,
          toX: 475,
          y: 38,
          progress: 0,
          speed: state.opMode === "replaying_memo" ? 0.022 : 0.009,
          r: 3.0,
          color: "#38bdf8",
          burstOnArrive: false,
        });
      } else {
        // Gentle heartbeat probe between NOVA (70) and EXEC (205) during headroom hold
        state.busParticles.push({
          fromX: 70,
          toX: 205,
          y: 38,
          progress: 0,
          speed: 0.012,
          r: 2.8,
          color: "#fbbf24",
          burstOnArrive: false,
        });
      }
    }

    const nextParticles = [];
    const svgParts = [];

    for (const p of state.busParticles) {
      p.progress += p.speed;
      if (p.progress >= 1) {
        if (p.burstOnArrive) {
          state.busRings.push({ x: p.toX, y: p.y, r: 12, alpha: 0.95, color: p.color });
        }
        continue;
      }
      nextParticles.push(p);
      const x = p.fromX + (p.toX - p.fromX) * p.progress;
      svgParts.push(
        `<circle cx="${x.toFixed(1)}" cy="${p.y}" r="${p.r}" fill="${p.color}" opacity="0.95"/>`
      );
    }
    state.busParticles = nextParticles;

    const nextRings = [];
    for (const rg of state.busRings) {
      rg.r += 0.85;
      rg.alpha -= 0.032;
      if (rg.alpha <= 0) continue;
      nextRings.push(rg);
      svgParts.push(
        `<circle cx="${rg.x}" cy="${rg.y}" r="${rg.r.toFixed(1)}" fill="none" stroke="${
          rg.color
        }" stroke-width="2.2" opacity="${rg.alpha.toFixed(2)}"/>`
      );
    }
    state.busRings = nextRings;

    layer.innerHTML = svgParts.join("");
  }

  function drawShardMosaic(nowMs) {
    const canvas = $("shard-mosaic-canvas");
    if (!canvas || state.activeTab !== "live") return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width;
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    const wsl = (state.live && state.live.wsl_prover) || {};
    const prog = wsl.progress || {};
    const tail = prog.mosaic_tail || [];

    const cols = 40;
    const rows = 8;
    const maxSlots = cols * rows - 1; // Reserve final slot for active in-flight indicator
    const slice = tail.slice(-maxSlots);

    const gap = 3;
    const cellW = (W - gap * (cols + 1)) / cols;
    const cellH = (H - gap * (rows + 1)) / rows;

    const rects = [];
    for (let i = 0; i < slice.length; i++) {
      const item = slice[i];
      const col = i % cols;
      const row = Math.floor(i / cols);
      const x = gap + col * (cellW + gap);
      const y = gap + row * (cellH + gap);

      const isReduce = item.t === 1;
      const isReplayed = item.r === 1;
      ctx.fillStyle = isReduce
        ? isReplayed
          ? "rgba(167, 139, 250, 0.42)"
          : "#a78bfa"
        : isReplayed
        ? "rgba(251, 191, 36, 0.38)"
        : "#fbbf24";

      ctx.beginPath();
      ctx.roundRect(x, y, cellW, cellH, 2);
      ctx.fill();

      if (state.hoveredTile && state.hoveredTile.idx === i) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      rects.push({
        idx: i,
        x,
        y,
        w: cellW,
        h: cellH,
        key: item.k,
        kind: item.t,
        replayed: isReplayed,
        sec: item.s,
        inFlight: false,
      });
    }

    // Active In-Flight Leading Slot
    const leadIdx = slice.length;
    const lCol = leadIdx % cols;
    const lRow = Math.floor(leadIdx / cols);
    const lx = gap + lCol * (cellW + gap);
    const ly = gap + lRow * (cellH + gap);
    const pulse = 0.45 + 0.55 * Math.sin(nowMs / 240);
    const activeColor =
      state.opMode === "waiting_headroom" || state.opMode === "cooldown_backoff"
        ? `rgba(251, 191, 36, ${0.35 + 0.55 * pulse})`
        : `rgba(56, 189, 248, ${0.4 + 0.6 * pulse})`;

    ctx.fillStyle = activeColor;
    ctx.beginPath();
    ctx.roundRect(lx, ly, cellW, cellH, 2);
    ctx.fill();

    ctx.strokeStyle = "#e0f2fe";
    ctx.lineWidth = 1.2;
    ctx.strokeRect(lx - 1, ly - 1, cellW + 2, cellH + 2);

    rects.push({
      idx: leadIdx,
      x: lx,
      y: ly,
      w: cellW,
      h: cellH,
      inFlight: true,
    });
    state.mosaicRects = rects;

    // Draw completion bursts over ignited tiles
    const aliveBursts = [];
    for (const b of state.tileBursts) {
      const age = nowMs - b.born;
      if (age > b.duration) continue;
      aliveBursts.push(b);
      const localIdx = Math.max(0, Math.min(slice.length - 1, b.idx - Math.max(0, tail.length - slice.length)));
      const col = localIdx % cols;
      const row = Math.floor(localIdx / cols);
      const cx = gap + col * (cellW + gap) + cellW / 2;
      const cy = gap + row * (cellH + gap) + cellH / 2;
      const t = age / b.duration;
      const radius = 4 + t * 26;
      const alpha = (1 - t) * 0.95;

      ctx.save();
      ctx.strokeStyle = b.color;
      ctx.lineWidth = 2.2 * (1 - t * 0.5);
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = "#ffffff";
      ctx.globalAlpha = Math.max(0, 1 - t * 2);
      ctx.beginPath();
      ctx.arc(cx, cy, cellW * 0.65, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
    state.tileBursts = aliveBursts;
  }

  // --- Campaign Sidebar & Banner ---
  function renderCampaignList() {
    const list = $("campaign-list");
    list.innerHTML = state.campaigns
      .map((c) => {
        const isLive = c.id === "ark-cashu-live";
        const active = c.id === state.selectedCampaignId ? "active" : "";
        const sm = c.summary_metrics || {};
        return `
          <button type="button" class="campaign-btn ${active}" data-cid="${esc(c.id)}">
            <div class="campaign-btn-top">
              <span>${esc(c.title.split("(")[0].trim())}</span>
              <span class="dot ${isLive ? "live" : "cyan"}"></span>
            </div>
            <span class="campaign-btn-sub">${esc(sm.domain_items_label || c.network)}</span>
          </button>`;
      })
      .join("");

    list.querySelectorAll(".campaign-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedCampaignId = btn.dataset.cid;
        renderCampaignList();
        renderSelectedCampaign();
      });
    });
  }

  function renderSelectedCampaign() {
    const c = getCampaign(state.selectedCampaignId);
    if (!c) return;
    const sm = c.summary_metrics || {};
    const wsl = (state.live && state.live.wsl_prover) || {};
    const prog = wsl.progress || {};

    $("campaign-network").textContent = c.network;
    $("campaign-title").textContent = c.title;
    $("campaign-subtitle").textContent = c.subtitle;
    $("campaign-hw").textContent = c.hardware;

    const badge = $("campaign-badge");
    badge.textContent = c.evidence_badge;
    badge.className = "status-pill " + (c.id === "ark-cashu-live" ? "live" : "cyan");

    const coreShards =
      c.id === "ark-cashu-live" && prog.unique_shards !== undefined
        ? prog.unique_shards
        : sm.sp1_core_shards;
    const recShards =
      c.id === "ark-cashu-live" && prog.unique_reduces !== undefined
        ? prog.unique_reduces
        : sm.sp1_recursion_shards;

    $("kpi-domain").textContent = sm.domain_items_label || "--";
    $("kpi-domain-foot").textContent = c.evidence_level;
    $("kpi-nova").textContent = `${fmtInt(sm.nova_segments)} seg · ${fmtInt(sm.nova_steps)} steps`;
    $("kpi-nova-foot").textContent = `${fmtInt(sm.constraints_per_step)} R1CS / step`;
    $("kpi-core-shards").textContent = fmtInt(coreShards);
    const exp = sm.sp1_element_threshold ? Math.round(Math.log2(sm.sp1_element_threshold)) : 27;
    $("kpi-threshold-foot").textContent = `Threshold 2^${exp} (${fmtInt(sm.sp1_element_threshold)})`;
    $("kpi-rec-shards").textContent = fmtInt(recShards);
    const ratio =
      coreShards && recShards
        ? `${(coreShards / recShards).toFixed(2)}:1 shard:reduce`
        : "~3:1 compress tree";
    $("kpi-fanin-foot").textContent = ratio;
    $("kpi-gates").textContent = `${(Number(sm.final_gates || 785442492) / 1e6).toFixed(2)}M`;
    $("kpi-mem-foot").textContent = sm.ram_peak_label || "M14 non-free AND gates";

    const stages =
      c.pipeline_stages ||
      (getCampaign("m16-mainnet-pay") && getCampaign("m16-mainnet-pay").pipeline_stages) ||
      [];
    $("pipeline-track").innerHTML = stages
      .map(
        (s) => `
      <article class="stage-card ${esc(s.state)}">
        <span class="stage-badge ${esc(s.state)}">${esc(s.state)}</span>
        <h3>${esc(s.stage)}</h3>
        <p>${esc(s.detail)}</p>
        <code>${esc(s.artifact)}</code>
      </article>`
      )
      .join("");

    renderShardHierarchy(c, coreShards, recShards);
  }

  // --- Live Telemetry Ingestion ---
  function ingestLiveSnapshot(d) {
    state.live = d;
    state.lastSamplePerfMs = performance.now();

    const wsl = d.wsl_prover || {};
    const lv = wsl.liveness || {};
    const prog = wsl.progress || {};

    state.opMode = lv.mode || "proving_inflight";
    state.basePhaseElapsedS = Number(lv.phase_elapsed_s || 0);
    state.baseCooldownRemS = Number(lv.cooldown_remaining_s || 0);
    state.baseTaskElapsedS = Number(lv.current_task_elapsed_s || 0);

    // Pulse SSE frame indicator
    const pill = $("sse-heartbeat-pill");
    if (pill) {
      $("sse-frame-label").textContent = `LIVE FRAME #${d.frame_seq || 1} · 1.0s`;
      pill.classList.add("pulse-hit");
      setTimeout(() => pill.classList.remove("pulse-hit"), 320);
    }

    // Detect newly completed shards/reduces since last frame!
    const seq = Number(prog.seq || 0);
    if (state.lastSeenSeq !== null && seq > state.lastSeenSeq) {
      const delta = (prog.recent_events || []).filter((e) => e.seq > state.lastSeenSeq);
      delta.slice(-16).forEach((ev, idx) => {
        setTimeout(() => emitShardCompletionVisual(ev), idx * 120);
      });
    }
    state.lastSeenSeq = seq;

    renderLiveTelemetry();
  }

  function renderLiveTelemetry() {
    const d = state.live;
    if (!d) return;

    const gpu = d.gpu || {};
    const hm = d.host_memory || {};
    const hg = d.host_guard || {};
    const wsl = d.wsl_prover || {};
    const lv = wsl.liveness || {};
    const prog = wsl.progress || {};
    const sess = wsl.session_summary || {};
    const latestRes = wsl.latest_resource || {};
    const limits = wsl.limits || {};

    // Update Live Cockpit
    const cockpit = $("liveness-cockpit");
    if (cockpit) {
      const isHold = lv.mode === "waiting_headroom" || lv.mode === "cooldown_backoff";
      cockpit.className = `liveness-cockpit ${isHold ? "mode-waiting" : "mode-proving"}`;
      $("cockpit-attempt-tag").textContent = `Attempt #${wsl.attempt_count || 1} · ${
        wsl.gpu_host_holds || 0
      } holds`;
      $("cockpit-headline").textContent = lv.headline || "Monitoring WSL prover…";
      $("cockpit-detail").textContent = lv.detail || "";

      const wire = $("bus-active-wire");
      if (wire) {
        wire.setAttribute("x2", isHold ? "205" : "475");
        wire.setAttribute("stroke", isHold ? "var(--amber)" : "var(--cyan)");
      }

      if (isHold) {
        $("cockpit-bar-left").textContent = `Windows Free RAM Headroom vs Auto-Resume Target`;
        $("cockpit-bar-right").textContent = `${lv.headroom_current_gib} / ${lv.headroom_target_gib} GiB (${lv.headroom_pct}%)`;
        const fill = $("cockpit-progress-fill");
        fill.style.width = `${lv.headroom_pct || 0}%`;
        fill.className = "meter-fill " + ((lv.headroom_pct || 0) >= 100 ? "emerald" : "amber");
      } else {
        const expS = Math.max(30, lv.expected_task_s || 300);
        const curS = lv.current_task_elapsed_s || 0;
        const pct = Math.min(99, (curS / expS) * 100);
        $("cockpit-bar-left").textContent = `In-Flight CUDA Task Progress (${wsl.inflight_artifacts || 0} live DAG artifacts)`;
        $("cockpit-bar-right").textContent = `${curS.toFixed(1)}s / ~${Math.round(expS)}s mean`;
        const fill = $("cockpit-progress-fill");
        fill.style.width = `${Math.max(4, pct).toFixed(1)}%`;
        fill.className = "meter-fill cyan";
      }
    }

    // 1. GPU Card
    if (gpu.available) {
      $("gpu-name-label").textContent = gpu.name.replace("NVIDIA GeForce ", "");
      $("gpu-pstate-label").textContent = gpu.pstate || "CUDA";
      $("gpu-util-val").textContent = `${Math.round(gpu.util_gpu_pct)}% GPU`;
      const vUsed = Math.round(gpu.vram_used_mib);
      const vTot = Math.round(gpu.vram_total_mib || 16303);
      $("gpu-vram-val").textContent = `${fmtInt(vUsed)} / ${fmtInt(vTot)} MiB`;
      $("gpu-vram-bar").style.width = `${Math.min(100, (vUsed / vTot) * 100).toFixed(1)}%`;
      $("gpu-temp-power").textContent = `${gpu.temp_c}°C · ${Number(gpu.power_draw_w || 0).toFixed(1)}W`;
      $("gpu-clock-pool").textContent = `${gpu.clock_sm_mhz}MHz · 256M cap`;
    } else {
      $("gpu-util-val").textContent = "N/A";
    }

    // 2. Host & WSL RAM Card
    if (hm.supported) {
      const availGiB = Number(fmtGiB(hm.avail_phys_bytes));
      const usedGiB = Number(fmtGiB(hm.used_phys_bytes, 1));
      const totGiB = Number(fmtGiB(hm.total_phys_bytes, 1));
      $("host-avail-val").textContent = `${availGiB.toFixed(2)} GiB free`;
      $("host-used-val").textContent = `${usedGiB} / ${totGiB} GiB`;
      const pct = Math.min(100, (hm.used_phys_bytes / hm.total_phys_bytes) * 100);
      const bar = $("host-ram-bar");
      bar.style.width = `${pct.toFixed(1)}%`;
      bar.className = "meter-fill " + (availGiB < 3.2 ? "red" : availGiB < 5.0 ? "amber" : "emerald");
      $("host-guard-badge").textContent = hg.stop_reason
        ? hg.stop_reason === "host_memory_floor"
          ? "TRIP · 3G FLOOR"
          : `TRIP · ${hg.stop_reason}`
        : `FLOOR ${(Number(hg.memory_floor_bytes || 3221225472) / 1073741824).toFixed(1)}G`;

      const vm = hm.vmmem_wsl;
      if (vm && vm.working_set_bytes !== undefined) {
        $("vmmem-ws-label").textContent = `WSL WS: ${fmtGiB(vm.working_set_bytes, 2)}G`;
        $("vmmem-commit-label").textContent = `Commit: ${fmtGiB(vm.private_commit_bytes, 2)}G`;
      } else {
        $("vmmem-ws-label").textContent = "vmmemWSL: idle";
        $("vmmem-commit-label").textContent = `SysCommit: ${fmtGiB(hm.used_commit_bytes, 1)}G`;
      }
    }

    // 3. WSL Cgroup v2 Card
    const rawPhase = wsl.reachable ? String(wsl.status || "idle") : "offline";
    const phasePretty =
      !wsl.phase_running && rawPhase.startsWith("waiting_for_headroom")
        ? "HOLD · HEADROOM"
        : !wsl.phase_running
        ? "PAUSED · HOLD"
        : rawPhase === "gpu"
        ? "GPU · CUDA"
        : rawPhase === "cpu"
        ? "CPU · RESUME"
        : rawPhase.toUpperCase();
    $("wsl-phase-badge").textContent = phasePretty;
    const cgRam = latestRes.cgroup_ram_mib ?? 0;
    const cgHard = limits.linux_ram_hard_mib || 2048;
    const cgSwap = latestRes.cgroup_swap_mib ?? 0;
    const swapMax = limits.swap_max_mib || 4096;
    $("cgroup-ram-val").textContent = wsl.phase_running
      ? `${fmtInt(Math.round(cgRam))} MiB`
      : "0 MiB (idle)";
    $("cgroup-cap-val").textContent = `/ ${fmtInt(cgHard)} MiB`;
    $("cgroup-ram-bar").style.width = `${Math.min(100, (cgRam / cgHard) * 100).toFixed(1)}%`;
    $("cgroup-swap-label").textContent = `Swap ${fmtInt(Math.round(cgSwap))}/${fmtInt(swapMax)}M`;

    const dFree =
      latestRes.d_free_gib ??
      (hm.disks && hm.disks["D:\\"] ? Number(fmtGiB(hm.disks["D:\\"].free_bytes, 1)) : "--");
    $("disk-free-label").textContent = `D: ${dFree}G free`;

    // 4. Active Shard Stream Card & Bus Counts
    const uShards = prog.unique_shards ?? 0;
    const uReduces = prog.unique_reduces ?? 0;
    $("live-shards-val").textContent = `${fmtInt(uShards)} shards`;
    $("live-reduces-val").textContent = `+ ${fmtInt(uReduces)} reduce`;
    if ($("bus-shard-count")) $("bus-shard-count").textContent = `${fmtInt(uShards)} core`;
    if ($("bus-reduce-count")) $("bus-reduce-count").textContent = `${fmtInt(uReduces)} reduce`;
    if ($("mosaic-total-count")) $("mosaic-total-count").textContent = fmtInt(uShards + uReduces);

    const rates = prog.rates || {};
    const combinedRate = Number(
      (rates.shard_per_min_15m || 0) + (rates.reduce_per_min_15m || 0)
    ).toFixed(1);
    $("shard-rate-badge").textContent = `${combinedRate} tasks/m`;
    const ratioPct = uShards + uReduces > 0 ? (uShards / (uShards + uReduces)) * 100 : 50;
    $("live-shard-bar").style.width = `${ratioPct.toFixed(1)}%`;
    $("session-proved-label").textContent =
      sess.session_shards_proved !== undefined
        ? `+${sess.session_shards_proved} sh / +${sess.session_recursion_proved} rec`
        : `${fmtInt((prog.proved_rows_by_kind || {}).shard || 0)} proved`;
    $("store-mib-label").textContent =
      sess.artifact_store_mib !== undefined
        ? `Store: ${fmtInt(sess.artifact_store_mib)} MiB`
        : `${fmtInt(prog.total_rows || 0)} rows`;

    $("active-phase-name").textContent = wsl.active_phase_dir || wsl.status || "--";
    if (wsl.phase_log_tail) {
      $("phase-log-pre").textContent = wsl.phase_log_tail;
    }

    const gEvents = wsl.guard_events || [];
    $("guard-events-tbody").innerHTML = gEvents.length
      ? gEvents
          .slice()
          .reverse()
          .map(
            (ev) => `
          <tr>
            <td class="mono">${ev.attempt ? `#${ev.attempt} · ` : ""}${esc(ev.stop_reason)}</td>
            <td class="mono">${esc(ev.exit_code)}</td>
            <td class="mono">${esc(ev.elapsed_s)}s</td>
            <td class="mono">${fmtInt(Math.round(ev.memory_peak_mib))} MiB</td>
            <td class="mono">${fmtInt(Math.round(ev.swap_peak_mib))} MiB</td>
            <td class="mono">${esc(ev.cleaned_shm_count)} files</td>
          </tr>`
          )
          .join("")
      : `<tr><td colspan="6" class="mono">No resource-guard interruptions recorded.</td></tr>`;

    renderCompletionFeed(prog.recent_events || []);
    renderMemoryAccounting(hm, hg, wsl, gpu);
    renderMemoryChart(wsl.resources_series || []);
    renderTaskAndGpuChart(prog.recent_events || [], gpu.history || []);

    if (state.selectedCampaignId === "ark-cashu-live") {
      renderSelectedCampaign();
    }
  }

  function renderCompletionFeed(events) {
    const feed = $("completion-feed");
    if (!feed) return;
    const latest = (events || []).slice(-8).reverse();
    if (!latest.length) {
      feed.innerHTML = `<div class="mono" style="color:var(--ink-dim)">Waiting for shard completions…</div>`;
      return;
    }
    const maxMs = Math.max(60000, ...latest.map((e) => e.ms || 1000));
    feed.innerHTML = latest
      .map((ev) => {
        const isReduce = ev.kind === "reduce";
        const pct = Math.max(8, Math.min(100, ((ev.ms || 1000) / maxMs) * 100));
        const sec = ((ev.ms || 0) / 1000).toFixed(1);
        const hi = state.highlightedSeqs.has(ev.seq) ? "newly-arrived" : "";
        const fillCol = isReduce ? "var(--violet)" : "var(--amber)";
        return `
          <div class="feed-item ${hi}">
            <span class="feed-kind ${isReduce ? "reduce" : "shard"}">${
          isReduce ? "REDUCE" : "SHARD"
        }</span>
            <span style="color:var(--ink)">${esc((ev.key || "").slice(0, 8))}</span>
            <div>
              <div class="feed-dur-bar"><div class="feed-dur-fill" style="width:${pct.toFixed(
                1
              )}%;background:${fillCol}"></div></div>
            </div>
            <span style="color:var(--ink-muted)">${sec}s · ${esc(fmtAgo(ev.t))}</span>
          </div>`;
      })
      .join("");
  }

  function renderMemoryAccounting(hm, _hg, wsl, gpu) {
    const vm = (hm && hm.vmmem_wsl) || {};
    const lr = wsl.latest_resource || {};
    const rows = [
      {
        label: "Windows Physical RAM",
        value: hm.supported
          ? `${fmtGiB(hm.used_phys_bytes, 2)} / ${fmtGiB(hm.total_phys_bytes, 2)} GiB (${hm.load_percent}%)`
          : "--",
        pct: hm.supported ? (hm.used_phys_bytes / hm.total_phys_bytes) * 100 : 0,
        cls: "emerald",
        note: `Available: ${fmtGiB(hm.avail_phys_bytes, 2)} GiB · Running floor: 3.00 GiB · Auto-resume target: ${(
          (wsl.startup_host_reserve_mib || 6144) / 1024
        ).toFixed(2)} GiB`,
      },
      {
        label: "vmmemWSL Resident vs Committed",
        value: vm.working_set_bytes
          ? `${fmtGiB(vm.working_set_bytes, 2)} GiB WS · ${fmtGiB(vm.private_commit_bytes, 2)} GiB Commit`
          : "N/A",
        pct: vm.private_commit_bytes
          ? Math.min(100, (vm.working_set_bytes / Math.max(1, vm.private_commit_bytes)) * 100)
          : 0,
        cls: "amber",
        note:
          vm.nonresident_commit_bytes !== undefined
            ? `Non-resident pagefile/compressed delta: ${fmtGiB(
                vm.nonresident_commit_bytes,
                2
              )} GiB (Task Manager shows WS only)`
            : "WSL VM memory process counters",
      },
      {
        label: "Prover Cgroup v2 (arkprove)",
        value: wsl.phase_running
          ? `${fmtInt(Math.round(lr.cgroup_ram_mib || 0))} MiB RSS + ${fmtInt(
              Math.round(lr.cgroup_swap_mib || 0)
            )} MiB Swap`
          : `Idle / Reclaimed (last peak ${fmtInt(Math.round((wsl.cgroup_peaks_mib || {}).ram_peak_mib || 0))} MiB)`,
        pct: Math.min(100, ((lr.cgroup_ram_mib || 0) / 2048) * 100),
        cls: "violet",
        note: `Soft watermark: 1,024 MiB · Hard memory.max: 2,048 MiB · memory.swap.max: 4,096 MiB`,
      },
      {
        label: "RTX 5080 Device & Driver Pool",
        value: gpu.available
          ? `${fmtInt(Math.round(gpu.vram_used_mib))} / ${fmtInt(Math.round(gpu.vram_total_mib))} MiB VRAM`
          : "--",
        pct: gpu.available ? (gpu.vram_used_mib / gpu.vram_total_mib) * 100 : 0,
        cls: "cyan",
        note: `ARK_SP1_TRANSIENT_TRACES=1 (exact-size trace lease) + libark_cuda_pool.so 256 MiB release cap`,
      },
    ];

    $("mem-accounting-list").innerHTML = rows
      .map(
        (r) => `
      <div class="mem-row">
        <div class="mem-row-top">
          <span>${esc(r.label)}</span>
          <code>${esc(r.value)}</code>
        </div>
        <div class="meter"><div class="meter-fill ${r.cls}" style="width:${r.pct.toFixed(1)}%"></div></div>
        <div class="mem-row-note">${esc(r.note)}</div>
      </div>`
      )
      .join("");
  }

  // --- SVG Charts ---
  function renderMemoryChart(series) {
    const svg = $("mem-history-svg");
    const W = 640;
    const H = 210;
    const pad = { l: 38, r: 12, t: 14, b: 24 };
    const pw = W - pad.l - pad.r;
    const ph = H - pad.t - pad.b;

    if (!series || series.length < 2) {
      svg.innerHTML = `<text x="${W / 2}" y="${H / 2}" text-anchor="middle" fill="#6e8098" font-size="12" font-family="monospace">Waiting for multi-point cgroup resource series…</text>`;
      return;
    }

    const maxY = Math.max(
      10,
      ...series.map((s) => Math.max(s.host_avail_gib || 0, (s.cgroup_swap_mib || 0) / 1024 + 1))
    );
    const xAt = (i) => pad.l + (i / (series.length - 1)) * pw;
    const yAt = (val) => pad.t + ph - Math.min(1, Math.max(0, val / maxY)) * ph;

    const poly = (getter) =>
      series.map((s, i) => `${xAt(i).toFixed(1)},${yAt(getter(s)).toFixed(1)}`).join(" ");

    const gridLines = [0, 3, 8, Math.round(maxY)]
      .filter((v, idx, arr) => v <= maxY && arr.indexOf(v) === idx)
      .map((v) => {
        const y = yAt(v).toFixed(1);
        const isFloor = v === 3;
        return `
          <line x1="${pad.l}" y1="${y}" x2="${W - pad.r}" y2="${y}"
            stroke="${isFloor ? "var(--red)" : "var(--line)"}"
            stroke-dasharray="${isFloor ? "5,4" : "2,3"}" stroke-width="${isFloor ? "1.4" : "1"}"/>
          <text x="${pad.l - 6}" y="${Number(y) + 4}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">${v}G</text>`;
      })
      .join("");

    const t0 = series[0].elapsed_s;
    const tN = series[series.length - 1].elapsed_s;

    svg.innerHTML = `
      ${gridLines}
      <polyline fill="none" stroke="var(--accent)" stroke-width="2" points="${poly(
        (s) => s.host_avail_gib || 0
      )}"/>
      <polyline fill="none" stroke="var(--cyan)" stroke-width="2" points="${poly(
        (s) => (s.cgroup_ram_mib || 0) / 1024
      )}"/>
      <polyline fill="none" stroke="var(--violet)" stroke-width="1.8" points="${poly(
        (s) => (s.cgroup_swap_mib || 0) / 1024
      )}"/>
      <text x="${pad.l}" y="${H - 6}" fill="var(--ink-dim)" font-size="10" font-family="monospace">t=${t0}s</text>
      <text x="${W - pad.r}" y="${H - 6}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">t=${tN}s (${
      series.length
    } samples)</text>
    `;
  }

  function renderTaskAndGpuChart(events, gpuHist) {
    const svg = $("task-history-svg");
    const W = 640;
    const H = 210;
    const pad = { l: 42, r: 14, t: 14, b: 24 };
    const pw = W - pad.l - pad.r;
    const ph = H - pad.t - pad.b;

    const proved = (events || []).filter((e) => !e.replayed && e.ms > 0);
    const items = proved.length >= 2 ? proved : events || [];
    if (!items.length && !gpuHist.length) {
      svg.innerHTML = `<text x="${W / 2}" y="${H / 2}" text-anchor="middle" fill="#6e8098" font-size="12" font-family="monospace">No recent shard events yet</text>`;
      return;
    }

    const maxSec = Math.max(60, ...items.map((e) => (e.ms || 1000) / 1000));
    const ySec = (s) => pad.t + ph - Math.min(1, Math.max(0, s / maxSec)) * ph;

    const barW = items.length ? Math.max(4, Math.min(18, pw / items.length - 3)) : 8;
    const bars = items
      .map((ev, idx) => {
        const x = pad.l + (idx / Math.max(1, items.length)) * pw;
        const sec = (ev.ms || 500) / 1000;
        const y = ySec(sec);
        const h = Math.max(3, pad.t + ph - y);
        const color = ev.kind === "reduce" ? "var(--violet)" : "var(--amber)";
        const opacity = ev.replayed ? "0.35" : "0.88";
        return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(
          1
        )}" height="${h.toFixed(1)}" rx="2" fill="${color}" opacity="${opacity}">
          <title>${esc(ev.kind)} ${esc(ev.key)} · ${sec.toFixed(1)}s (${
          ev.replayed ? "replayed" : "proved"
        })</title>
        </rect>`;
      })
      .join("");

    let vramLine = "";
    if (gpuHist && gpuHist.length >= 2) {
      const pts = gpuHist
        .map((g, i) => {
          const x = pad.l + (i / (gpuHist.length - 1)) * pw;
          const y = pad.t + ph - Math.min(1, (g.vram_used_mib || 0) / 16303) * ph;
          return `${x.toFixed(1)},${y.toFixed(1)}`;
        })
        .join(" ");
      vramLine = `<polyline fill="none" stroke="var(--cyan)" stroke-width="2" points="${pts}"/>`;
    }

    svg.innerHTML = `
      <line x1="${pad.l}" y1="${pad.t}" x2="${W - pad.r}" y2="${pad.t}" stroke="var(--line)" stroke-dasharray="2,3"/>
      <line x1="${pad.l}" y1="${pad.t + ph / 2}" x2="${W - pad.r}" y2="${pad.t + ph / 2}" stroke="var(--line)" stroke-dasharray="2,3"/>
      <line x1="${pad.l}" y1="${pad.t + ph}" x2="${W - pad.r}" y2="${pad.t + ph}" stroke="var(--line)"/>
      <text x="${pad.l - 6}" y="${pad.t + 4}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">${Math.round(
      maxSec
    )}s</text>
      <text x="${pad.l - 6}" y="${pad.t + ph / 2 + 4}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">${Math.round(
      maxSec / 2
    )}s</text>
      <text x="${pad.l - 6}" y="${pad.t + ph}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">0s</text>
      ${bars}
      ${vramLine}
      <text x="${pad.l}" y="${H - 6}" fill="var(--ink-dim)" font-size="10" font-family="monospace">Recent ${
      items.length
    } memo tasks</text>
      <text x="${W - pad.r}" y="${H - 6}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">VRAM scale: 0..16.3 GiB</text>
    `;
  }

  // --- Tab 02 & Tab 03 Static + Campaign Data ---
  function renderShardHierarchy(c, coreShards, recShards) {
    const sm = c.summary_metrics || {};
    const layers = [
      {
        tag: "L1 · BITCOIN PRIMITIVES",
        desc: `Blocks, Shinigami script leaves, payment UTXOs & Ark VTXOs (${c.network})`,
        count: sm.domain_items_label || "--",
      },
      {
        tag: "L2 · NOVA 0.76 FOLDING",
        desc: `Pallas/Vesta relaxed R1CS folding (${fmtInt(
          sm.constraints_per_step
        )} constraints/step) → Spartan-IPA bundles`,
        count: `${fmtInt(sm.nova_segments)} seg · ${fmtInt(sm.nova_steps)} steps`,
      },
      {
        tag: "L3 · SP1 CORE SHARDS",
        desc: `RISC-V guest execution sliced at element_threshold=${fmtInt(
          sm.sp1_element_threshold
        )} with M15 raw VK`,
        count: `${fmtInt(coreShards)} ProveShard`,
      },
      {
        tag: "L4 · SP1 RECURSION TREE",
        desc: `3:1 KoalaBear STARK compression tree → single SP1ProofWithPublicValues`,
        count: `${fmtInt(recShards)} RecursionReduce`,
      },
      {
        tag: "L5 · M13 BLAKE3 + M14 GARBLE",
        desc: `BLAKE3 Merkle/transcript v2 wrap → fixed Boolean garbled circuit verifier`,
        count: `${fmtInt(sm.final_gates || 785442492)} AND gates`,
      },
    ];

    $("shard-pyramid").innerHTML = layers
      .map(
        (l) => `
      <div class="pyramid-layer">
        <span class="pyramid-layer-tag">${esc(l.tag)}</span>
        <span class="pyramid-layer-desc">${esc(l.desc)}</span>
        <span class="pyramid-layer-count">${esc(l.count)}</span>
      </div>`
      )
      .join("");
  }

  function renderCampaignTables() {
    const m16 = getCampaign("m16-mainnet-pay");
    const m18 = getCampaign("m18-mainnet-utxo");
    const m17 = getCampaign("m17-shinigami-leaves");
    const ark = getCampaign("ark-cashu-live");

    if (m16 && m16.instruction_breakdown) {
      const colors = [
        "var(--cyan)",
        "var(--violet)",
        "var(--accent)",
        "var(--amber)",
        "#ec4899",
        "#94a3b8",
      ];
      $("m16-instr-bar").innerHTML = m16.instruction_breakdown
        .map(
          (row, idx) =>
            `<div class="stacked-seg" style="width:${Math.max(
              0.4,
              row.share_pct
            )}%;background:${colors[idx % colors.length]}" title="${esc(
              row.component
            )}: ${row.share_pct}%"></div>`
        )
        .join("");

      $("m16-instr-tbody").innerHTML = m16.instruction_breakdown
        .map((row) => {
          const shards = Math.max(1, Math.round((row.share_pct / 100) * 13290));
          return `
            <tr>
              <td>${esc(row.component)}</td>
              <td class="mono">${fmtInt(row.instructions)}</td>
              <td class="mono">${row.share_pct}%</td>
              <td class="mono">~${fmtInt(row.share_pct < 0.01 ? 1 : shards)}</td>
            </tr>`;
        })
        .join("");
    }

    if (m18 && m18.blocks && m18.blocks.length) {
      renderM18BlocksChart(m18.blocks);
      $("m18-blocks-tbody").innerHTML = m18.blocks
        .map(
          (b) => `
        <tr class="${b.contains_pay1 ? "selected-row" : ""}">
          <td class="mono"><strong>${fmtInt(b.height)}</strong> ${b.contains_pay1 ? "★ PAY1" : ""}</td>
          <td class="mono">${fmtInt(b.transactions)}</td>
          <td class="mono">${fmtInt(b.creates)}</td>
          <td class="mono">${fmtInt(b.spends_in_window)}</td>
          <td class="mono">${fmtInt(b.spends_before_window)}</td>
          <td class="mono">${fmtInt(b.sha256_compressions)}</td>
          <td class="mono">${fmtInt(b.poseidon_leaf_updates)}</td>
          <td class="mono">${fmtInt(b.idle_steps)}</td>
          <td class="mono"><strong>${fmtInt(b.nova_steps)}</strong></td>
          <td class="mono">${esc(b.segment_span)}</td>
        </tr>`
        )
        .join("");
    }

    if (m18 && m18.segments) {
      $("m18-segments-tbody").innerHTML = m18.segments
        .map(
          (s) => `
        <tr>
          <td class="mono">seg-${s.index}</td>
          <td class="mono">${fmtInt(s.start_step)} .. ${fmtInt(s.start_step + s.steps)}</td>
          <td class="mono">${fmtInt(s.steps)}</td>
          <td class="mono">${shortHex(s.z0_sha256, 6, 4)} → ${shortHex(s.zn_sha256, 6, 4)}</td>
          <td class="mono">${s.fold_hours}h (${s.sec_per_step}s/st)</td>
          <td class="mono">${fmtInt(s.proof_bytes)} B (${shortHex(s.proof_sha256, 6, 4)})</td>
        </tr>`
        )
        .join("");
    }

    if (m17 && m17.shinigami_leaves) {
      $("shinigami-tbody").innerHTML = m17.shinigami_leaves
        .map(
          (lf) => `
        <tr>
          <td class="mono">${esc(lf.id)}</td>
          <td>${esc(lf.kind)} ${
            lf.taproot_leaf ? '<span class="pill-action taproot">TAPROOT</span>' : ""
          }</td>
          <td class="mono">${fmtInt(lf.steps)}</td>
          <td class="mono">${fmtInt(lf.deferred_claims)}</td>
          <td class="mono">${lf.prove_s}s</td>
          <td class="mono">${fmtInt(lf.peak_ram_mb)} MB</td>
        </tr>`
        )
        .join("");
    }

    if (m16 && m16.payment_utxo) {
      const p = m16.payment_utxo;
      const leafInfo = (m18 && m18.utxo_map && m18.utxo_map.pay1_leaf) || {};
      const lf = leafInfo.leaf || {};
      const items = [
        ["Outpoint (TXID:Vout)", `${shortHex(p.txid, 12, 8)}:${p.vout}`],
        ["Value & Script Type", `${fmtInt(p.value_sats)} sats · P2WPKH`],
        ["Payment Block", `${fmtInt(p.block_height)} (${p.confirmations} confs → 975,072)`],
        ["SPV Merkle Depth", `Depth ${p.merkle_depth} in ${fmtInt(p.block_tx_count)}-tx block`],
        [
          "M18 Poseidon Leaf Index",
          `Leaf #${leafInfo.index ?? 8} of 74,593 (spent=${String(lf.spent ?? false)})`,
        ],
        ["Poseidon Key (248-bit)", shortHex(lf.key || "ad71905a…6d5f00", 12, 8)],
        ["Next Linked Leaf", `#${fmtInt(lf.next_index ?? 46940)} (${shortHex(lf.next_key, 10, 6)})`],
        [
          "Sealed Map Root (LE)",
          shortHex((m18 && m18.utxo_map && m18.utxo_map.root_le_hex) || "", 12, 8),
        ],
      ];
      $("pay1-kv-grid").innerHTML = items
        .map(([k, v]) => `<div class="kv-item"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`)
        .join("");

      const sibs = leafInfo.siblings || [];
      $("pay1-siblings-pre").textContent = JSON.stringify(
        {
          txid_display: p.txid,
          vout: p.vout,
          script_pubkey: p.script_pubkey,
          leaf_index: leafInfo.index ?? 8,
          leaf: lf,
          merkle_siblings_depth_20: sibs,
        },
        null,
        2
      );
    }

    if (ark) {
      const cb = ark.cashu_bridge || {};
      const arkItems = [
        [
          "Proof Grove Deposit",
          `${fmtInt(cb.deposit_sats)} sats → ${cb.cashu_dleq_proofs} DLEQ Cashu proofs`,
        ],
        [
          "Cashu → Bark Melt",
          `${fmtInt(cb.ark_vtxo_sats)} sats VTXO + ${fmtInt(cb.cashu_change_sats)} sats change`,
        ],
        ["Delegated Refresh", `9,770 sats successor (${cb.ark_refresh_fee_sats} sat fee)`],
        ["Offline Exit Claim", `${fmtInt(cb.offline_exit_claim_sats)} sats on-chain (ASP & mint offline)`],
      ];
      $("cashu-ark-kv").innerHTML = arkItems
        .map(([k, v]) => `<div class="kv-item"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`)
        .join("");

      $("ark-vtxos-tbody").innerHTML = (ark.ark_vtxo_decisions || [])
        .map((d) => {
          const cls = d.action === "refresh" ? "refresh" : "defer";
          return `
            <tr>
              <td class="mono">${esc(shortHex(d.id, 12, 8))}</td>
              <td><span class="pill-action ${cls}">${esc(d.action)}</span></td>
              <td class="mono">${fmtInt(d.before_sats)}</td>
              <td class="mono">${fmtInt(d.after_sats)}</td>
              <td class="mono">${fmtInt(d.fee_sats)}</td>
              <td class="mono">${fmtInt(d.expiry_height)}</td>
            </tr>`;
        })
        .join("");

      const pinRows = [
        [
          "M16 Mainnet Statement SHA-256",
          m16?.pins?.committed_values_sha256,
          "Verified on Mainnet + M14 Garbled",
        ],
        ["M16 SP1 Program Key Digest", m16?.pins?.program_vk_digest, "Pinned in m13/pins.json"],
        [
          "M18 Windowed UTXO Circuit VK",
          m18?.pins?.vk_sha256,
          "Rebuilt from circuit & verified (8 segs)",
        ],
        ["Ark ASP Policy Nova VK", ark?.pins?.nova_vk_sha256, "Verified on 4 live Bark VTXOs"],
        [
          "Ark ASP SP1 Program Key Digest",
          ark?.pins?.program_vk_digest,
          "Derived from ELF; proving on RTX 5080",
        ],
        [
          "M13 BLAKE3 Transcript-v2 Wrap VK",
          m16?.pins?.wrap_vk_sha256,
          "Shared across Guest A, M16 & Ark",
        ],
        [
          "Cross-Program Substitution Gate",
          "M16 wrap proof → ARK1 verifier",
          "REFUSED (different committed statement)",
        ],
      ];
      $("pins-tbody").innerHTML = pinRows
        .map(
          ([name, hex, st]) => `
        <tr>
          <td><strong>${esc(name)}</strong></td>
          <td class="mono">${esc(hex)}</td>
          <td class="mono">${esc(st)}</td>
        </tr>`
        )
        .join("");
    }
  }

  function renderM18BlocksChart(blocks) {
    const svg = $("m18-blocks-svg");
    const W = 860;
    const H = 200;
    const pad = { l: 54, r: 20, t: 16, b: 30 };
    const pw = W - pad.l - pad.r;
    const ph = H - pad.t - pad.b;
    const maxSteps = Math.max(45000, ...blocks.map((b) => b.nova_steps));
    const groupW = pw / blocks.length;

    const bars = blocks
      .map((b, i) => {
        const gx = pad.l + i * groupW + groupW * 0.14;
        const bw = groupW * 0.24;
        const hComp = (b.sha256_compressions / maxSteps) * ph;
        const hLeaf = (b.poseidon_leaf_updates / maxSteps) * ph;
        const hIdle = (b.idle_steps / maxSteps) * ph;
        const baseY = pad.t + ph;
        return `
          <rect x="${gx.toFixed(1)}" y="${(baseY - hComp).toFixed(1)}" width="${bw.toFixed(
          1
        )}" height="${hComp.toFixed(1)}" rx="3" fill="var(--cyan)"/>
          <rect x="${(gx + bw + 4).toFixed(1)}" y="${(baseY - hLeaf).toFixed(
          1
        )}" width="${bw.toFixed(1)}" height="${hLeaf.toFixed(1)}" rx="3" fill="var(--accent)"/>
          ${
            b.idle_steps > 0
              ? `<rect x="${(gx + 2 * (bw + 4)).toFixed(1)}" y="${(baseY - hIdle).toFixed(
                  1
                )}" width="${(bw * 0.8).toFixed(1)}" height="${Math.max(4, hIdle).toFixed(
                  1
                )}" rx="2" fill="var(--amber)"/>`
              : ""
          }
          <text x="${(gx + bw).toFixed(1)}" y="${H - 9}" text-anchor="middle" fill="var(--ink-muted)" font-size="11" font-family="monospace">${
          b.height
        }</text>
          <text x="${(gx + bw).toFixed(1)}" y="${(
          baseY -
          Math.max(hComp, hLeaf) -
          5
        ).toFixed(1)}" text-anchor="middle" fill="var(--ink-dim)" font-size="10" font-family="monospace">${fmtInt(
          b.nova_steps
        )}</text>
        `;
      })
      .join("");

    svg.innerHTML = `
      <line x1="${pad.l}" y1="${pad.t}" x2="${W - pad.r}" y2="${pad.t}" stroke="var(--line)" stroke-dasharray="2,3"/>
      <line x1="${pad.l}" y1="${pad.t + ph / 2}" x2="${W - pad.r}" y2="${pad.t + ph / 2}" stroke="var(--line)" stroke-dasharray="2,3"/>
      <line x1="${pad.l}" y1="${pad.t + ph}" x2="${W - pad.r}" y2="${pad.t + ph}" stroke="var(--line)"/>
      <text x="${pad.l - 8}" y="${pad.t + 4}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">${fmtInt(
      maxSteps
    )}</text>
      <text x="${pad.l - 8}" y="${pad.t + ph / 2 + 4}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">${fmtInt(
      Math.round(maxSteps / 2)
    )}</text>
      <text x="${pad.l - 8}" y="${pad.t + ph}" text-anchor="end" fill="var(--ink-dim)" font-size="10" font-family="monospace">0</text>
      ${bars}
    `;
  }

  // --- Tab 04: Workload -> Shard & Hardware Estimator ---
  function scheduleCorrelate() {
    clearTimeout(state.correlateTimer);
    state.correlateTimer = setTimeout(runCorrelate, 110);
  }

  async function runCorrelate() {
    const payload = {
      header_blocks: Number($("est-header-blocks").value),
      nova_header_shards: Number($("est-header-shards").value),
      utxo_window_blocks: Number($("est-window-blocks").value),
      payment_utxos: Number($("est-payment-utxos").value),
      shinigami_leaves: Number($("est-shinigami-leaves").value),
      ark_vtxos: Number($("est-ark-vtxos").value),
      shinigami_script_type: $("est-script-type").value,
      element_threshold_exp: Number($("est-threshold").value),
      hardware_profile: $("est-hw-profile").value,
    };

    try {
      const resp = await fetch("/api/correlate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) return;
      const res = await resp.json();
      renderEstimate(res);
    } catch (_err) {
      // Ignore transient network errors
    }
  }

  function renderEstimate(res) {
    const nv = res.nova || {};
    const sp = res.sp1 || {};
    const rc = res.resources || {};
    const cards = [
      ["Nova Segments & Steps", `${fmtInt(nv.total_segments)} segs · ${fmtInt(nv.total_steps)} steps`],
      ["Total R1CS Constraints", fmtInt(nv.total_r1cs_constraints)],
      ["M18 Indexed UTXO Leaves", fmtInt(nv.m18_indexed_utxo_leaves)],
      ["SP1 Guest Instructions", fmtInt(sp.total_instructions)],
      ["SP1 Core Shards (ProveShard)", fmtInt(sp.core_shards)],
      ["SP1 Recursive Shards (Reduce)", fmtInt(sp.recursion_shards)],
      ["Linux Cgroup RAM + Swap", `${rc.linux_cgroup_ram_gib} GiB RAM + ${rc.linux_swap_gib} GiB swap`],
      [
        "RTX 5080 VRAM / Host Reserve",
        `${rc.gpu_vram_gib} GiB VRAM · ${rc.windows_host_reserve_gib} GiB Win floor`,
      ],
      ["Memo Disk Footprint", `~${rc.memo_disk_gib} GiB`],
      ["Est. Wall Time (Nova + SP1)", `${rc.estimated_sp1_hours}h SP1 + ${nv.estimated_fold_hours}h Nova`],
    ];
    $("est-results-grid").innerHTML = cards
      .map(([k, v]) => `<div class="kv-item"><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`)
      .join("");

    $("est-total-tasks-tag").textContent = `${fmtInt(sp.total_tasks)} total memo tasks`;

    const attr = sp.shard_attribution || {};
    const parts = [
      ["Header Blocks", attr.header_blocks || 0, "var(--cyan)"],
      ["UTXO Window + Payments", attr.utxo_window_and_payments || 0, "var(--accent)"],
      ["Shinigami Leaves", attr.shinigami_leaves || 0, "var(--violet)"],
      ["Ark VTXO Policy", attr.ark_vtxo_policy || 0, "var(--amber)"],
    ];
    const sum = Math.max(1, parts.reduce((acc, p) => acc + p[1], 0));
    $("est-attr-bar").innerHTML = parts
      .filter((p) => p[1] > 0)
      .map(
        ([name, val, col]) =>
          `<div class="stacked-seg" style="width:${((val / sum) * 100).toFixed(
            1
          )}%;background:${col}" title="${esc(name)}: ${fmtInt(val)} shards"></div>`
      )
      .join("");
    $("est-attr-legend").innerHTML = parts
      .map(
        ([name, val, col]) =>
          `<span class="legend-item"><i class="legend-swatch" style="background:${col}"></i>${esc(
            name
          )}: ${fmtInt(val)} shards</span>`
      )
      .join("");
  }

  // --- SSE Live Stream + Fallback Polling ---
  async function fetchCampaigns() {
    const resp = await fetch("/api/campaigns");
    if (!resp.ok) return;
    const data = await resp.json();
    state.campaigns = data.campaigns || [];
    renderCampaignList();
    renderCampaignTables();
    renderSelectedCampaign();
  }

  async function fetchLiveOnce() {
    try {
      const resp = await fetch("/api/live");
      if (!resp.ok) return;
      ingestLiveSnapshot(await resp.json());
    } catch (_err) {
      $("poll-label").textContent = "Server unreachable — retrying…";
    }
  }

  function connectStream() {
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
    if (!state.polling || typeof EventSource === "undefined") {
      return;
    }

    const es = new EventSource("/api/stream");
    state.eventSource = es;

    es.addEventListener("telemetry", (ev) => {
      try {
        const snap = JSON.parse(ev.data);
        $("poll-label").textContent = "Live 1s SSE stream active";
        ingestLiveSnapshot(snap);
      } catch (_e) {
        // Ignore malformed frame
      }
    });

    es.onerror = () => {
      es.close();
      state.eventSource = null;
      if (state.polling) {
        $("poll-label").textContent = "SSE reconnecting (fallback poll)…";
        setTimeout(() => {
          if (state.polling && !state.eventSource) connectStream();
        }, 2500);
      }
    };
  }

  async function boot() {
    initControls();
    startAnimationLoop();
    await Promise.all([fetchCampaigns(), fetchLiveOnce(), runCorrelate()]);
    connectStream();
    // Backup poll if SSE is ever disconnected
    state.fallbackTimer = setInterval(() => {
      if (state.polling && !state.eventSource) fetchLiveOnce();
    }, 2000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
