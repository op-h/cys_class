(() => {
  const D = JSON.parse(document.getElementById("sim-data").textContent);
  const RM = matchMedia("(prefers-reduced-motion: reduce)");
  const slides = [...document.querySelectorAll(".slide")];
  const root = document.documentElement;
  root.classList.add("deck");

  // Slides are authored at 1280x720; one scaled stage keeps every slide pixel-identical to the PDF.
  const stage = document.createElement("div");
  stage.className = "stage";
  slides[0].before(stage);
  slides.forEach((s) => stage.append(s));
  const fit = () => stage.style.setProperty("--s", Math.min(innerWidth / 1280, innerHeight / 720));
  addEventListener("resize", fit);
  fit();

  // ---------- Controls ----------
  document.body.insertAdjacentHTML("beforeend", `
    <div class="progress" aria-hidden="true"><i></i></div>
    <nav class="deck-ui" aria-label="Slide controls">
      <button type="button" data-go="-1" aria-label="Previous slide">‹</button>
      <span aria-live="polite"></span>
      <button type="button" data-go="1" aria-label="Next slide">›</button>
      <button type="button" data-fs aria-label="Toggle fullscreen">⛶</button>
    </nav>
    <div class="toast" role="status"><kbd>←</kbd> <kbd>→</kbd> or click / scroll to move · click a terminal to type commands · <kbd>F</kbd> fullscreen</div>`);
  const counter = document.querySelector(".deck-ui span");
  const bar = document.querySelector(".progress i");
  const toast = document.querySelector(".toast");
  setTimeout(() => toast.classList.add("gone"), 5000);

  const fullscreen = () => {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    else root.requestFullscreen?.().catch(() => {});
  };
  document.querySelector(".deck-ui").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    if (b.hasAttribute("data-fs")) fullscreen();
    else go(cur + Number(b.dataset.go));
  });

  // ---------- Navigation ----------
  let cur = Math.min(Math.max((parseInt(location.hash.slice(1), 10) || 1) - 1, 0), slides.length - 1);
  let running = [];
  const EASE_IN = "cubic-bezier(.16,1,.3,1)", EASE_OUT = "cubic-bezier(.4,0,.2,1)";

  function paint() {
    slides.forEach((s, i) => { s.classList.toggle("on", i === cur); s.inert = i !== cur; });
    counter.textContent = `${cur + 1} / ${slides.length}`;
    bar.style.width = `${((cur + 1) / slides.length) * 100}%`;
    history.replaceState(null, "", `#${cur + 1}`);
  }

  function entrance(slide) {
    const parts = slide.querySelectorAll(".kicker, h1, h2, .desc, .syn, .flags tr, .use, .sub, .meta, .ag, .big li, .task, .term");
    parts.forEach((el, i) => running.push(el.animate(
      [{ opacity: 0, transform: "translateY(16px)" }, { opacity: 1, transform: "none" }],
      { duration: 520, delay: 90 + i * 38, easing: EASE_IN, fill: "backwards" })));
    [...slide.querySelectorAll(".screen .ln")].slice(0, 24).forEach((el, i) => running.push(el.animate(
      [{ opacity: 0, transform: "translateX(-6px)" }, { opacity: 1, transform: "none" }],
      { duration: 280, delay: 320 + i * 32, easing: "ease-out", fill: "backwards" })));
  }

  function go(n) {
    n = Math.min(Math.max(n, 0), slides.length - 1);
    if (n === cur) return;
    running.forEach((a) => a.finish());
    running = [];
    const dir = n > cur ? 1 : -1, from = slides[cur], to = slides[n];
    if (document.activeElement && from.contains(document.activeElement)) document.activeElement.blur();
    cur = n;
    paint();
    if (RM.matches) return;
    from.classList.add("out");
    const out = from.animate(
      [{ opacity: 1, transform: "none" }, { opacity: 0, transform: `translateX(${-dir * 6}%) scale(.94)` }],
      { duration: 480, easing: EASE_OUT });
    out.finished.catch(() => {}).finally(() => from.classList.remove("out"));
    running.push(out, to.animate(
      [{ opacity: 0, transform: `translateX(${dir * 9}%) scale(1.03)` }, { opacity: 1, transform: "none" }],
      { duration: 640, easing: EASE_IN }));
    entrance(to);
  }

  addEventListener("keydown", (e) => {
    if (e.target.classList?.contains("sim-in")) {
      if (e.key === "PageDown") { e.preventDefault(); go(cur + 1); }
      if (e.key === "PageUp") { e.preventDefault(); go(cur - 1); }
      return;
    }
    if (e.target.closest?.("button") && (e.key === " " || e.key === "Enter")) return;
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const k = e.key;
    if (["ArrowRight", "ArrowDown", "PageDown", " "].includes(k)) { e.preventDefault(); go(cur + 1); }
    else if (["ArrowLeft", "ArrowUp", "PageUp"].includes(k)) { e.preventDefault(); go(cur - 1); }
    else if (k === "Home") go(0);
    else if (k === "End") go(slides.length - 1);
    else if (k === "f" || k === "F") fullscreen();
  });

  // Click: left quarter goes back, anywhere else goes forward. Interactive bits keep their own clicks.
  stage.addEventListener("click", (e) => {
    if (e.target.closest(".term, .chips, button, a, input")) return;
    if (String(getSelection())) return;
    go(e.clientX < innerWidth / 4 ? cur - 1 : cur + 1);
  });

  let wheelSum = 0, wheelLock = 0;
  addEventListener("wheel", (e) => {
    const scr = e.target.closest?.(".screen");
    if (scr && scr.scrollHeight > scr.clientHeight) return; // let a long terminal scroll
    if (Date.now() < wheelLock) return;
    wheelSum += e.deltaY || e.deltaX;
    if (Math.abs(wheelSum) > 40) {
      go(cur + Math.sign(wheelSum));
      wheelSum = 0;
      wheelLock = Date.now() + 700;
    }
  }, { passive: true });

  let tx = null;
  addEventListener("touchstart", (e) => { tx = e.touches[0].clientX; }, { passive: true });
  addEventListener("touchend", (e) => {
    if (tx === null) return;
    const dx = e.changedTouches[0].clientX - tx;
    tx = null;
    if (Math.abs(dx) > 50) go(cur + (dx < 0 ? 1 : -1));
  }, { passive: true });

  addEventListener("hashchange", () => go((parseInt(location.hash.slice(1), 10) || 1) - 1));

  // ---------- Terminal simulator ----------
  const key = (s) => s.trim().replace(/\s+/g, " ").replace(/"/g, "'");
  const GLOBAL = new Map();
  D.sims.forEach((sim) => sim.ex.forEach(([c, out]) => { if (!GLOBAL.has(key(c))) GLOBAL.set(key(c), out); }));

  document.querySelectorAll(".term[data-sim]").forEach((term) => {
    const sim = D.sims[Number(term.dataset.sim)];
    const local = new Map(sim.ex.map(([c, out]) => [key(c), out]));
    const screen = term.querySelector(".screen");
    const live = screen.querySelector(".ln.live");
    const pc = live.querySelector(".pc");
    const label = sim.cmd ? `Terminal simulator for ${sim.cmd}` : "Terminal simulator";
    live.insertAdjacentHTML("beforeend", `<input class="sim-in" type="text" spellcheck="false" autocomplete="off" autocapitalize="off" aria-label="${label}">`);
    const input = live.querySelector(".sim-in");
    term.querySelector(".bar").insertAdjacentHTML("beforeend", '<em class="hint">click to type · help · Esc to leave</em>');
    term.addEventListener("click", () => { if (!String(getSelection())) input.focus({ preventScroll: true }); });

    const hist = [];
    let hi = 0, cwd = "~", oldCwd = "~", typing = false, tabIdx = 0;

    const line = (text, cls) => {
      const d = document.createElement("div");
      d.className = "ln" + (cls ? " " + cls : "") + (text.startsWith("# ") && !cls ? " co" : "");
      d.textContent = text || " ";
      live.before(d);
    };
    const echo = (cmd) => {
      const d = document.createElement("div");
      d.className = "ln";
      d.innerHTML = '<span class="pr">kali@kali</span><span class="pc"></span> <span class="cm"></span>';
      d.querySelector(".pc").textContent = `:${cwd}$`;
      d.querySelector(".cm").textContent = cmd;
      live.before(d);
    };
    const examples = (list, head) => {
      line(head, "tip");
      list.slice(0, 4).forEach((c) => line("  " + c, "tip"));
    };
    const resolve = (p) => {
      const home = "/home/kali";
      let base = cwd === "~" ? home : cwd;
      if (!p || p === "~") return home;
      if (p.startsWith("~")) p = home + p.slice(1);
      const parts = (p.startsWith("/") ? [] : base.split("/").filter(Boolean));
      p.split("/").filter(Boolean).forEach((seg) => { if (seg === "..") parts.pop(); else if (seg !== ".") parts.push(seg); });
      return "/" + parts.join("/");
    };
    const show = (p) => (p === "/home/kali" ? "~" : p.startsWith("/home/kali/") ? "~" + p.slice(10) : p);

    function run(raw) {
      const cmd = raw.trim().replace(/\s+/g, " ");
      echo(raw);
      if (!cmd) return;
      hist.push(cmd);
      hi = hist.length;
      const [w0, ...rest] = cmd.split(" ");

      if (w0 === "clear") { [...screen.querySelectorAll(".ln:not(.live)")].forEach((n) => n.remove()); return; }
      if (w0 === "help") {
        ["Simulator commands:",
         "  hint            example commands for this slide",
         "  man <cmd>       quick reference for any of the 50 commands",
         "  <cmd> --help    same as man",
         "  history / clear",
         "Keys: Tab completes · ↑/↓ history · Esc leaves the terminal"].forEach((t) => line(t, "tip"));
        return;
      }
      if (w0 === "hint" || w0 === "examples") {
        if (sim.ex.length) examples(sim.ex.map((x) => x[0]), "Try typing one of these:");
        else line("No examples on this slide. Type help.", "tip");
        return;
      }
      if (w0 === "history") { hist.forEach((h, i) => line(`${String(i + 1).padStart(5)}  ${h}`)); return; }
      if (w0 === "exit" || w0 === "logout") { line("# This is a simulator: press Esc, then → for the next slide."); return; }
      const helpTarget = w0 === "man" ? rest[0] : (rest.includes("--help") ? w0 : null);
      if (helpTarget !== null && helpTarget !== undefined) {
        const info = D.info[helpTarget];
        if (!info) { line(`No manual entry for ${helpTarget}`, "err"); return; }
        line("NAME"); line(`       ${helpTarget} - ${info.desc}`);
        line("SYNOPSIS"); line(`       ${info.syntax}`);
        line("OPTIONS");
        info.flags.forEach(([f, m]) => line(`       ${f.padEnd(14)} ${m}`));
        return;
      }
      if (w0 === "man") { line("What manual page do you want? Try: man " + (sim.cmd || "grep"), "err"); return; }
      if (w0 === "cd" && !cmd.includes("&&")) {
        const target = rest[0] === "-" ? (oldCwd === "~" ? "/home/kali" : oldCwd) : resolve(rest[0]);
        if (rest[0] === "-") line(target);
        oldCwd = cwd;
        cwd = show(target);
        pc.textContent = `:${cwd}$`;
        return;
      }
      if (cmd === "pwd") { line(resolve(".")); return; }

      const k = key(cmd);
      const alt = k.startsWith("sudo ") ? k.slice(5) : "sudo " + k;
      const out = local.get(k) ?? local.get(alt) ?? GLOBAL.get(k) ?? GLOBAL.get(alt);
      if (out) { out.forEach((t) => line(t)); return; }

      if (w0 === "whoami") { line("kali"); return; }
      if (w0 === "echo") { line(rest.join(" ").replace(/^(['"])(.*)\1$/, "$2")); return; }
      if (w0 === "date") { line(new Date().toString()); return; }
      if (cmd === "ls") { line("Desktop  Documents  Downloads  case01  lab-tmp  quarantine  scripts"); return; }

      const name = w0 === "sudo" ? rest[0] : w0;
      if (D.info[name]) {
        line(`[simulator] '${cmd}' isn't in this lab's recorded output.`, "tip");
        examples(D.info[name].ex, `Recorded examples for ${name}:`);
        return;
      }
      line(`zsh: command not found: ${w0}`, "err");
    }

    const scroll = () => { screen.scrollTop = screen.scrollHeight; };
    input.addEventListener("keydown", (e) => {
      if (typing) { e.preventDefault(); return; }
      if (e.key === "Enter") { run(input.value); input.value = ""; tabIdx = 0; scroll(); }
      else if (e.key === "Escape") input.blur();
      else if (e.key === "ArrowUp" && hist.length) { e.preventDefault(); hi = Math.max(0, hi - 1); input.value = hist[hi]; }
      else if (e.key === "ArrowDown") { e.preventDefault(); hi = Math.min(hist.length, hi + 1); input.value = hist[hi] ?? ""; }
      else if (e.key === "Tab" && input.value) {
        // Only intercept Tab when there is something to complete, so keyboard users are never trapped.
        const matches = sim.ex.map((x) => x[0]).filter((c) => c.startsWith(input.value) && c !== input.value);
        if (matches.length) { e.preventDefault(); input.value = matches[tabIdx++ % matches.length]; }
      } else if (e.key === "l" && e.ctrlKey) { e.preventDefault(); run("clear"); }
    });

    const typeRun = async (cmd) => {
      if (typing) return;
      input.focus({ preventScroll: true });
      if (!RM.matches) {
        typing = true;
        input.value = "";
        for (const ch of cmd) { input.value += ch; await new Promise((r) => setTimeout(r, 22)); }
        await new Promise((r) => setTimeout(r, 180));
        typing = false;
      }
      run(cmd);
      input.value = "";
      scroll();
    };

    // "Try" buttons under the practice task
    const task = term.closest(".slide").querySelector(".task");
    if (task && sim.ex.length) {
      const chips = document.createElement("div");
      chips.className = "chips";
      sim.ex.slice(0, 3).forEach(([c]) => {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = c;
        b.title = `Run in the terminal: ${c}`;
        b.addEventListener("click", () => typeRun(c));
        chips.append(b);
      });
      task.append(chips);
    }
  });

  paint();
})();
