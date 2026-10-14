# Frontend decisions (feature/frontend)

Each entry gives the choice, the alternatives we considered, and the reason. Decisions owned by other
branches (crypto, auth, storage) are in their own documents and are not repeated here.

## 1. A mascot, Gembi, in the "Sticker" style
- **Choice:** a padlock character, Gembi (from *gembok*, Indonesian for "padlock"), drawn in style B "Sticker":
  ink outline, white sticker border, dot eyes.
- **Alternatives:** style A "Mochi" (no outlines) and style C "Keyhole guard" (shield shape with cap and key). All three
  are in `docs/design/mascot-preview/`, each in every mood.
- **Why:** the outline keeps Gembi readable at 28 px in the nav and on pastel backgrounds where A faded out.
  C had the most detail but looked busy when small. A padlock that reacts to what you do (it covers its eyes for
  passwords, gets busy while encrypting) also shows the app's security model in a friendly way.

## 2. Inline SVG partial with one mood class
- **Choice:** Gembi is an inline `<svg>` in `templates/mascot.html` (`{{template "mascot" "<mood>"}}`). Every face
  part has a class, and the mood is one class on the `<svg>` (`mascot--suspicious`, `mascot--busy`, …).
  `static/mascot.css` decides which parts show and which animation runs.
- **Alternatives:**
  - one image file per mood (`<img>`): CSS can't reach inside an image, so nothing could animate between moods;
  - `<use href="#gembi">`: class selectors from the page don't reach inside the `<use>` copy;
  - a JS animation library: an extra dependency, and the CSP would have to allow it.
- **Why:** with one class, the server picks the starting mood in the template and `mascot.js` only swaps that class.
  Every rule lives in CSS, so a mood can be checked by reading the stylesheet. The SVG is about 5 KB of markup per
  copy, which is fine for two copies per page (nav and main).

## 3. Gembi is decorative (`aria-hidden`)
- **Choice:** the SVG has `aria-hidden="true"`. Every state Gembi shows is also stated in text: the error list,
  the "Nothing stored yet" empty state, the disabled button reading "Locking it up…".
- **Alternatives:** `role="img"` with an `aria-label` that changes with each mood.
- **Why:** a label that changes every few seconds is noisy for screen-reader users. The text already carries
  the meaning, so Gembi never becomes the only way to learn something.

## 4. Motion only with transform/opacity, and none with reduced motion
- **Choice:** all animations change only `transform` and `opacity`. Under `prefers-reduced-motion: reduce` every
  animation and transition is switched off, but each mood keeps its static face. For example, "unlocked" still
  shows the shackle open and "confused" still tilts.
- **Alternatives:** shorter animations under reduced motion, or hiding Gembi.
- **Why:** transform and opacity animate without re-laying out the page. The reduced-motion rule follows
  WCAG 2.3.3 without losing any information. One-shot moods (angry, unlocked) use `animation-fill-mode: both` so
  re-adding the class replays them, and `mascot.js` settles back to the page's `data-base-mood` afterwards.

## 5. Self-hosted Nunito
- **Choice:** Nunito variable font, Latin subset (39 KB, SHA-256
  `BA344451EAB25B217A165363B1982048A5E5830A0DAF36577973955A04CAC793`) from
  `@fontsource-variable/nunito@5.3.0`, served from `/static/fonts/` with `OFL.txt` next to it. It uses `font-display: swap`
  and a `<link rel="preload">`.
- **Alternatives:** Google Fonts (blocked: the CSP's `default-src 'self'` covers fonts); a system font stack
  (looked different on every OS, and Windows has no rounded font).
- **Why:** it works under the CSP without loosening it, it sends no page views to a third party, and the SIL
  Open Font License allows bundling as long as the licence ships with the font.

## 6. All CSS/JS in static files, enforced by a test
- **Choice:** no `style=` attributes, `<style>` elements, inline `<script>`, `on*=` handlers or `javascript:` URLs
  in any template. `TestTemplatesAreCSPSafe` renders every page with empty and full data and fails if any of these appear.
- **Alternatives:** adding nonces or `'unsafe-inline'` to the CSP; relying on code review.
- **Why:** the CSP from the scaffold is strict on purpose, because it limits what an XSS bug could do. An inline
  handler would just stop working in the browser with only a console warning. The test turns that silent
  failure into a failing CI run.

## 7. Two scripts: `mascot.js` and `app.js`
- **Choice:** `mascot.js` handles only Gembi's moods. `app.js` handles everything else: marking the current nav
  link, auto-submitting the profile algorithm select, and closing flash messages.
- **Alternatives:** one combined script.
- **Why:** each file has one job, so it is easy to explain and review. Both are tiny and loaded with `defer`.
  Every page still works without JavaScript: the select keeps a "Show" button and forms submit normally.

## 8. Template data contracts for other branches
The templates read only data the handlers already pass, plus three keys whose producers belong to other
branches. The templates handle these keys being absent, so every page renders today:

| Key | Template | Producer | Notes |
|---|---|---|---|
| `.Files[].Name` | files.html | feature/file-storage | `FileRecord.FileName` is stored encrypted (`SealedSet`); `List` decrypts it ("decrypt filenames for display"), and the plaintext needs a field such as a view row or a `bson:"-"` field. |
| `.JustLoggedIn` | files.html | feature/auth | One-time flag after a successful login, so Gembi plays the unlock animation once. |
| `.Flash` (`.Kind`, `.Message`) | layout.html | feature/auth (sessions) | A message that survives a redirect after a POST, for example "File deleted". |

`.Errors` may be a slice or a map: `{{range}}` handles both, so feature/auth and feature/private-data can choose.
Missing keys in a `gin.H` are simply falsy in `if`/`with`.

## 9. `humanBytes` template function
- **Choice:** a single formatting function that shows file sizes in binary units ("1.5 KiB"). Values that would round
  to 1024 move up a unit, so the page never shows "1024.0 KiB".
- **Alternatives:** raw byte counts; formatting in every handler.
- **Why:** it keeps formatting in the view, where it belongs, and it is a pure function, so it is easy to
  test with edge cases (0, negative, 1023/1024, MiB−1, MaxInt64).

## 10. Friendly 404 page via `NoRoute`
- **Choice:** unknown paths, including missing `/static` files, render `error.html` (confused Gembi, status
  code, link home). The template takes `.Status` and `.Message`, so other branches can reuse it (for example a
  422 when a download fails its HMAC check).
- **Alternatives:** Gin's plain-text "404 page not found".
- **Why:** the page keeps the app's look, and it never shows internal error text: `.Message` is always a
  fixed, user-facing string chosen by the handler.

## 11. Tables become cards on phones
- **Choice:** under 600 px every table row becomes a card. Each cell's column name comes from `data-label`
  via `content: attr(data-label)`.
- **Alternatives:** horizontal scrolling inside the table; hiding columns.
- **Why:** nothing is hidden or cut off on a phone, and it needs only CSS. A generated `content` value is
  not an inline style, so the CSP allows it.

## 12. SVG favicon of Gembi
- **Choice:** `static/favicon.svg`, Gembi's smiling face drawn with the same shapes as the partial, linked from the
  layout with `<link rel="icon" type="image/svg+xml">`. Colours are presentation attributes, because a favicon is
  loaded as an image and can't use `mascot.css`.
- **Alternatives:** a `favicon.ico`/PNG set (binary files we would have to generate, with an extra tool); a
  `/favicon.ico` route (only needed by browsers that ignore `<link rel="icon">`).
- **Why:** one small text file that stays sharp at every size and can be reviewed like code. It is served from
  `/static`, so the CSP's `img-src 'self'` covers it. An SVG opened directly could run script, so
  `TestFaviconIsStaticSVG` fails if it ever gains a script, an event handler, an external reference or an animation.

## 13. "Strawberry milk" palette, every colour a token, contrast checked by a test
- **Choice:** blush pink background (`#fff3f6`), white cards, plum ink (`#47283a`), a raspberry accent (`#b3325f`) and
  a true red for errors (`#a8201a`). Gembi and the favicon use matching pinks. Every colour is a variable in one
  block: `:root` in `style.css`, `.mascot` in `mascot.css`. The other rules only use `var()`.
- **Alternatives:** the original cream theme; Periwinkle, Matcha and a dark "Midnight plum". All four candidates
  are in `docs/design/palette-preview/`, each on a mini copy of the UI with its contrast table.
- **Why:**
  - **Look:** the team found the cream background dull. Pink is the friendliest of the four and suits Gembi.
  - **Errors stay red:** with a pink accent, a pink-red error colour would blend in, so errors use a separate,
    clearly red `--danger`.
  - **Contrast:** every text colour is at least 4.5:1 on the backgrounds it is drawn on (WCAG 1.4.3 AA). The lowest
    is 5.0:1, the download pill on hover.
  - **Field borders:** form-field borders were too faint (1.2:1), so inputs, selects and textareas now have their
    own `--field-line` at 3.6:1 on cards (WCAG 1.4.11 asks for 3:1). Dividers and button outlines keep the light
    `--line` because they are decoration: a button is identified by its text.
  - **Tokens:** `style.css` used to hard-code a few colours (white field and button backgrounds, the primary hover).
    With everything as a token, a new palette or a later dark mode is one block of variables.
- **Enforced by tests** (`internal/web/theme_test.go`):
  - `TestStylesheetColoursOnlyInTokens` fails on a colour literal outside the token blocks;
  - `TestThemeContrast` recomputes the WCAG ratio of every text/background pair from the tokens;
  - `TestFaviconMatchesMascot` fails if `favicon.svg` uses a colour that is not one of Gembi's variables. The favicon
    can't load `mascot.css`, so it repeats the colours and could otherwise drift.
