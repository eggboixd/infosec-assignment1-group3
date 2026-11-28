// Small page helpers that are not about the mascot (that is mascot.js).
// addEventListener only: the Content-Security-Policy forbids inline handlers.
(function () {
  "use strict";

  // Mark the current section in the nav, for styling and screen readers.
  const path = window.location.pathname;
  document.querySelectorAll(".site-nav a[href]").forEach((link) => {
    const href = link.getAttribute("href");
    if (path === href || path.startsWith(href + "/")) link.setAttribute("aria-current", "page");
  });

  // <select data-autosubmit> reloads its GET form when changed. The form's
  // [data-autosubmit-button] stays in the HTML for users without JavaScript
  // and is hidden here.
  document.querySelectorAll("select[data-autosubmit]").forEach((select) => {
    const form = select.form;
    if (!form) return;
    form.querySelectorAll("[data-autosubmit-button]").forEach((button) => {
      button.hidden = true;
    });
    select.addEventListener("change", () => form.requestSubmit());
  });

  // <form data-confirm="question"> asks before submitting. Without
  // JavaScript the form just submits.
  document.addEventListener("submit", (event) => {
    const question = event.target.getAttribute("data-confirm");
    if (question && !window.confirm(question)) event.preventDefault();
  });

  // Dismissible flash messages.
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-dismiss]");
    const flash = button && button.closest(".flash");
    if (flash) flash.remove();
  });
})();
