// Wiring for the mascot preview page. Only addEventListener, no inline
// handlers, so the page follows the same CSP rules as the app.
(function () {
  "use strict";

  const MOODS = [
    { id: "suspicious", label: "Suspicious", use: "Login / register, idle" },
    { id: "covering", label: "Covering eyes", use: "Password field focused" },
    { id: "angry", label: "Angry", use: "Wrong password (shakes once)" },
    { id: "unlocked", label: "Unlocked", use: "Login success (plays once)" },
    { id: "smiling", label: "Smiling", use: "Dashboard, blinks" },
    { id: "busy", label: "Busy", use: "Uploading / encrypting" },
    { id: "happy", label: "Happy", use: "Downloading" },
    { id: "sleepy", label: "Sleepy", use: "Empty state" },
    { id: "confused", label: "Confused", use: "Error / 404" },
  ];
  const ONE_SHOT = ["angry", "unlocked"];
  const STATUS = {
    suspicious: "Suspicious: who goes there?",
    covering: "Covering eyes: I'm not looking at your password!",
    angry: "Angry: that's not the right password!",
    unlocked: "Unlocked! Welcome back.",
    smiling: "Smiling: here's your stuff (dashboard).",
    busy: "Busy: locking it up with AES, DES and RC4…",
    happy: "Happy: here's your file, decrypted.",
    sleepy: "Sleepy: nothing stored yet…",
    confused: "Confused: that page doesn't exist.",
  };

  const root = document.documentElement;
  const osReduce = window.matchMedia("(prefers-reduced-motion: reduce)");

  function reducedMotion() {
    return osReduce.matches || root.classList.contains("simulate-reduced-motion");
  }

  function setMood(svg, mood) {
    MOODS.forEach((m) => svg.classList.remove("mascot--" + m.id));
    svg.classList.add("mascot--" + mood);
    svg.dataset.mood = mood;
    svg.setAttribute("aria-label", "Padlock mascot, " + mood);
  }

  function createMascot(style, mood) {
    const tpl = document.getElementById("mascot-" + style);
    const svg = tpl.content.firstElementChild.cloneNode(true);
    setMood(svg, mood);
    return svg;
  }

  // Restart a one-shot animation by re-adding the mood class. Reading the
  // layout in between makes the browser drop the old animation first.
  function replay(svg) {
    const cls = "mascot--" + svg.dataset.mood;
    svg.classList.remove(cls);
    svg.getBoundingClientRect();
    svg.classList.add(cls);
  }

  // ---------- Static mascots (hero) and galleries ----------

  document.querySelectorAll("[data-mascot]").forEach((slot) => {
    slot.append(createMascot(slot.dataset.mascot, slot.dataset.mood));
  });

  document.querySelectorAll("[data-gallery]").forEach((grid) => {
    const style = grid.dataset.gallery;
    MOODS.forEach((m) => {
      const card = document.createElement("figure");
      card.className = "mood-card";
      const stage = document.createElement("div");
      stage.className = "mood-stage";
      stage.append(createMascot(style, m.id));

      const caption = document.createElement("figcaption");
      const title = document.createElement("strong");
      title.textContent = m.label;
      const use = document.createElement("span");
      use.textContent = m.use;
      const cls = document.createElement("code");
      cls.textContent = "mascot--" + m.id;
      caption.append(title, use, cls);

      card.append(stage, caption);
      grid.append(card);
    });
  });

  window.setInterval(() => {
    if (reducedMotion()) return;
    const sel = ONE_SHOT.map((id) => ".gallery .mascot--" + id).join(",");
    document.querySelectorAll(sel).forEach(replay);
  }, 3200);

  // ---------- Live demo ----------

  const stage = document.getElementById("demo-stage");
  const status = document.getElementById("demo-status");
  const form = document.getElementById("demo-form");
  const pass = document.getElementById("demo-pass");
  const chipRow = document.getElementById("demo-moods");
  const demo = { style: "a", svg: null, timer: 0 };

  function syncChips(mood) {
    chipRow.querySelectorAll(".chip").forEach((chip) => {
      chip.setAttribute("aria-pressed", String(chip.dataset.mood === mood));
    });
  }

  // show sets the demo mood; with `then`, it falls back to that mood after
  // `delay` ms (used after the one-shot angry/unlocked reactions).
  function show(mood, then, delay) {
    window.clearTimeout(demo.timer);
    if (demo.svg.dataset.mood === mood) {
      replay(demo.svg);
    } else {
      setMood(demo.svg, mood);
    }
    status.textContent = STATUS[mood];
    syncChips(mood);
    if (then) {
      demo.timer = window.setTimeout(() => show(then), delay);
    }
  }

  function mountDemo() {
    const mood = demo.svg ? demo.svg.dataset.mood : "suspicious";
    demo.svg = createMascot(demo.style, mood);
    stage.replaceChildren(demo.svg);
  }

  MOODS.forEach((m) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip";
    chip.dataset.mood = m.id;
    chip.textContent = m.label;
    chip.addEventListener("click", () => show(m.id));
    chipRow.append(chip);
  });

  document.querySelectorAll('input[name="demo-style"]').forEach((radio) => {
    radio.addEventListener("change", () => {
      demo.style = radio.value;
      mountDemo();
    });
  });

  pass.addEventListener("focus", () => show("covering"));
  pass.addEventListener("blur", () => {
    if (demo.svg.dataset.mood === "covering") show("suspicious");
  });

  function wrong() {
    show("angry", "suspicious", 1400);
  }
  function right() {
    show("unlocked", "smiling", 2200);
  }

  document.getElementById("demo-wrong").addEventListener("click", wrong);
  document.getElementById("demo-right").addEventListener("click", right);

  // The demo form never leaves the page: nothing is sent or stored.
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const ok = pass.value === "letmein";
    pass.value = "";
    pass.blur();
    if (ok) right();
    else wrong();
  });

  // ---------- Reduced motion ----------

  const reduceToggle = document.getElementById("demo-reduce");
  const osNote = document.getElementById("demo-os-motion");

  function describeOs() {
    osNote.textContent = osReduce.matches
      ? "Your OS already asks for reduced motion, so nothing animates here."
      : "Your OS allows motion. Tick the box to see the static versions.";
  }
  reduceToggle.addEventListener("change", () => {
    root.classList.toggle("simulate-reduced-motion", reduceToggle.checked);
  });
  osReduce.addEventListener("change", describeOs);
  describeOs();

  mountDemo();
  syncChips("suspicious");
})();
