// Gembi's mood changes on the page.
//
// The server renders Gembi in a starting mood (templates/mascot.html). This
// script only reacts to what happens in the browser: password focus, form
// submits, download clicks and deleted rows. It works by swapping one
// mascot--<mood> class (see static/mascot.css). It uses addEventListener only
// because the Content-Security-Policy forbids inline scripts and handlers.
// Without JavaScript Gembi simply keeps the mood the server chose.
//
// Page hooks (data attributes):
//   [data-gembi]                 wraps the page's main mascot
//   data-base-mood="..."         on [data-gembi]: the mood to settle back to
//   input[data-gembi-cover]      Gembi covers its eyes while it has focus
//   form[data-gembi-busy="..."]  Gembi is busy while it submits (value = button label)
//   a[data-gembi-download]       Gembi is happy for a moment when clicked
//   [data-gembi-list]            a <tbody>; when its last row is removed, Gembi
//                                gets sleepy and [data-gembi-empty] is shown
(function () {
  "use strict";

  const stage = document.querySelector("[data-gembi]");
  const svg = stage && stage.querySelector(".mascot");
  if (!svg) return;

  const MOODS = ["suspicious", "covering", "angry", "unlocked", "smiling", "busy", "happy", "sleepy", "confused", "hello"];
  // How long the one-shot moods play before settling (matches mascot.css).
  const ONE_SHOT_MS = { angry: 1400, unlocked: 2200, hello: 1300 };
  const HAPPY_MS = 2500;

  let base = MOODS.includes(stage.dataset.baseMood) ? stage.dataset.baseMood : "smiling";
  let timer = 0;

  function setMood(mood) {
    MOODS.forEach((m) => svg.classList.remove("mascot--" + m));
    svg.classList.add("mascot--" + mood);
    svg.dataset.mood = mood;
  }

  // show switches to mood. With ms, Gembi settles back to the base mood
  // afterwards. Showing the current mood again restarts its animation
  // (reading the layout in between makes the browser drop the old one).
  function show(mood, ms) {
    window.clearTimeout(timer);
    if (svg.dataset.mood === mood) {
      svg.classList.remove("mascot--" + mood);
      svg.getBoundingClientRect();
    }
    setMood(mood);
    if (ms) timer = window.setTimeout(() => setMood(base), ms);
  }

  // A one-shot mood from the server (wrong password, just logged in) plays
  // once and then settles.
  const initial = svg.dataset.mood;
  if (ONE_SHOT_MS[initial]) timer = window.setTimeout(() => setMood(base), ONE_SHOT_MS[initial]);

  // Cover the eyes while any password field has focus. The blur check waits
  // one tick so moving between two password fields doesn't flicker.
  document.querySelectorAll("input[data-gembi-cover]").forEach((input) => {
    input.addEventListener("focus", () => show("covering"));
    input.addEventListener("blur", () => {
      window.setTimeout(() => {
        const active = document.activeElement;
        const stillCovering = active && active.matches("input[data-gembi-cover]");
        if (!stillCovering && svg.dataset.mood === "covering") show(base);
      }, 0);
    });
  });

  // Busy while a form that encrypts something is being sent. The submit is
  // not stopped; the button is disabled so it can't be sent twice.
  document.querySelectorAll("form[data-gembi-busy]").forEach((form) => {
    form.addEventListener("submit", () => {
      show("busy");
      const button = form.querySelector('button[type="submit"]');
      if (button) {
        button.dataset.label = button.textContent;
        button.textContent = form.dataset.gembiBusy || "Locking it up…";
        button.disabled = true;
      }
    });
  });

  // Coming back with the Back button can restore the page as it was left
  // (busy, button disabled), so reset it.
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    document.querySelectorAll("form[data-gembi-busy] button[data-label]").forEach((button) => {
      button.textContent = button.dataset.label;
      button.disabled = false;
    });
    show(base);
  });

  // Happy for a moment when a decrypted download starts. Delegated, so rows
  // added later by htmx work too.
  document.addEventListener("click", (event) => {
    if (event.target.closest("a[data-gembi-download]")) show("happy", HAPPY_MS);
  });

  // When the last row of the list is removed (htmx delete), show the empty
  // state and let Gembi nap.
  const list = document.querySelector("[data-gembi-list]");
  if (list) {
    new MutationObserver(() => {
      if (list.querySelector("tr")) return;
      const table = list.closest("table");
      if (table) table.hidden = true;
      const empty = document.querySelector("[data-gembi-empty]");
      if (empty) empty.hidden = false;
      base = "sleepy";
      show(base);
    }).observe(list, { childList: true });
  }
})();
