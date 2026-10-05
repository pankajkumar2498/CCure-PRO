/**
 * The in-page census. `census.toString()` is evaluated inside the page, so this
 * function must be self-contained: no imports, no closures over module scope.
 *
 * Every value it returns is deterministic for a settled page with a frozen
 * clock — lists are sorted and nothing records a timestamp — so two captures
 * of one build compare equal and any difference is a difference in the page.
 */
export function census(opts) {
  const tracked = (opts && opts.tracked) || [];

  const textOf = (el) =>
    (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim();
  const visible = (el) => {
    if (!el.getClientRects().length) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== "hidden" && cs.display !== "none";
  };
  const short = (s, n = 48) => (s.length > n ? `${s.slice(0, n)}…` : s);
  const pathOf = (el) => {
    const parts = [];
    for (
      let n = el, i = 0;
      n && n !== document.body && i < 3;
      n = n.parentElement, i += 1
    ) {
      const cls = [...n.classList]
        .filter((c) => c !== "cc-sr-only")
        .slice(0, 2)
        .join(".");
      parts.unshift(
        n.tagName.toLowerCase() +
          (n.id ? `#${n.id}` : "") +
          (cls ? `.${cls}` : ""),
      );
    }
    return parts.join(">");
  };
  const labelFor = (el) => {
    const ids = el.getAttribute("aria-labelledby");
    if (ids) {
      const t = ids
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map(textOf)
        .join(" ")
        .trim();
      if (t) return t;
    }
    const al = el.getAttribute("aria-label");
    if (al && al.trim()) return al.trim();
    if (el.id) {
      const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
      if (l && textOf(l)) return textOf(l);
    }
    const wrap = el.closest("label");
    if (wrap && textOf(wrap)) return textOf(wrap);
    return "";
  };
  const nameOf = (el) => {
    const l = labelFor(el);
    if (l) return l;
    if (/^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName)) return "";
    if (el.tagName === "IMG") return (el.getAttribute("alt") || "").trim();
    return textOf(el) || (el.getAttribute("title") || "").trim();
  };
  const glyphOnly = (s) => !/[\p{L}\p{N}]/u.test(s);

  /* ── Names ───────────────────────────────────────────────────────────── */
  const buttons = [...document.querySelectorAll("button,[role=button]")].filter(
    visible,
  );
  const links = [...document.querySelectorAll("a[href],[role=link]")].filter(
    visible,
  );
  const controls = [
    ...document.querySelectorAll("input:not([type=hidden]),select,textarea"),
  ].filter(visible);
  const names = {
    buttons: buttons.length,
    buttonNames: buttons.map((b) => short(nameOf(b))).sort(),
    buttonsUnnamed: buttons
      .filter((b) => !nameOf(b))
      .map(pathOf)
      .sort(),
    buttonsGlyphOnly: buttons
      .filter((b) => {
        const n = nameOf(b);
        return n && glyphOnly(n);
      })
      .map((b) => `${pathOf(b)}:${nameOf(b)}`)
      .sort(),
    links: links.length,
    linkNames: links.map((l) => short(nameOf(l))).sort(),
    linksUnnamed: links
      .filter((l) => !nameOf(l))
      .map(pathOf)
      .sort(),
    controls: controls.length,
    controlsUnlabelled: controls
      .filter((c) => !labelFor(c))
      .map(pathOf)
      .sort(),
  };

  /* ── Structure ───────────────────────────────────────────────────────── */
  const headings = [...document.querySelectorAll("h1,h2,h3,h4,h5,h6")]
    .filter(visible)
    .map((h) => `${h.tagName.toLowerCase()}:${short(textOf(h), 60)}`);

  const roles = {};
  for (const el of document.querySelectorAll("[role]")) {
    const r = el.getAttribute("role");
    roles[r] = (roles[r] || 0) + 1;
  }

  const STATE_ATTRS = [
    "aria-sort",
    "aria-pressed",
    "aria-selected",
    "aria-expanded",
    "aria-current",
    "aria-busy",
    "aria-modal",
    "aria-invalid",
    "aria-checked",
    "aria-disabled",
  ];
  const ariaStates = [];
  for (const attr of STATE_ATTRS) {
    for (const el of document.querySelectorAll(`[${attr}]`)) {
      ariaStates.push(
        `${attr}=${el.getAttribute(attr)}@${el.tagName.toLowerCase()}:${short(nameOf(el), 40)}`,
      );
    }
  }
  ariaStates.sort();

  const dialogs = [
    ...document.querySelectorAll("[role=dialog],[role=alertdialog],dialog"),
  ]
    .filter(visible)
    .map(
      (d) =>
        `${d.getAttribute("role") || "dialog"}|modal=${d.getAttribute("aria-modal")}|${short(labelFor(d), 60)}`,
    )
    .sort();

  const live = {
    status: document.querySelectorAll("[role=status]").length,
    alert: document.querySelectorAll("[role=alert]").length,
    ariaLive: document.querySelectorAll("[aria-live]").length,
  };

  const tables = [...document.querySelectorAll("table")]
    .filter(visible)
    .map((t) => {
      const direct = t.querySelectorAll(":scope > caption").length;
      const all = t.querySelectorAll("caption").length;
      const ths = t.querySelectorAll("th");
      return {
        captions: direct,
        misplacedCaptions: all - direct,
        captionFirst: t.firstElementChild?.tagName === "CAPTION",
        caption: short(
          textOf(t.querySelector("caption") || document.createElement("i")),
          60,
        ),
        th: ths.length,
        thScoped: [...ths].filter((th) => th.hasAttribute("scope")).length,
        sortButtons: t.querySelectorAll("thead th button").length,
        ariaSort: [...t.querySelectorAll("th[aria-sort]")].map(
          (th) => `${short(textOf(th), 24)}=${th.getAttribute("aria-sort")}`,
        ),
        rows: t.querySelectorAll("tbody tr").length,
      };
    });

  const inline = [...document.querySelectorAll("[style]")]
    .filter((el) => el.tagName !== "HTML" && el.tagName !== "BODY")
    .map(
      (el) =>
        `${el.tagName.toLowerCase()}.${[...el.classList].slice(0, 2).join(".")}:${el.getAttribute("style")}`,
    )
    .sort();

  /* Per-element signatures as well as totals. On a page that already uses a
     legacy class, a legacy class added to an element that already carries
     another changes neither the element count nor the set of names — the
     sensitivity gate caught exactly that. */
  const dbClasses = new Set();
  const dbSignatures = new Set();
  let dbElements = 0;
  let dbTokens = 0;
  for (const el of document.querySelectorAll("[class]")) {
    const hits = [...el.classList].filter((c) => c.startsWith("db-"));
    if (hits.length) {
      dbElements += 1;
      dbTokens += hits.length;
      hits.forEach((c) => dbClasses.add(c));
      dbSignatures.add(`${el.tagName.toLowerCase()}:${hits.sort().join(" ")}`);
    }
  }
  const classes = {
    dbElements,
    dbTokens,
    dbClasses: [...dbClasses].sort(),
    dbSignatures: [...dbSignatures].sort(),
    ccElements: [...document.querySelectorAll("[class*='cc-']")].length,
  };

  /* ── Pointer-only affordances ────────────────────────────────────────────
     An element that shows a pointer cursor but is not a control and sits
     inside no control is a click target a keyboard cannot reach. Only the
     outermost such element is counted (cursor inherits to its children).

     Batch 18: `[tabindex]` used to count as a control in the ancestor test.
     The application shell renders `<main tabIndex={-1}>` (the skip link's
     target) around every page, so every element on every page sat "inside a
     control" and this list was always empty. A focusable container is not a
     control. An element is exempt when it is, or sits inside, a real control,
     or when it is itself reachable by Tab. */
  const CONTROL =
    "a[href],button,input,select,textarea,summary,label,[role=button],[role=link],[role=tab],[role=checkbox],[role=radio],[role=menuitem],[role=option],[role=switch]";
  const TABBABLE_SELF = '[tabindex]:not([tabindex^="-"])';
  const clickable = [];
  for (const el of document.body.querySelectorAll("*")) {
    if (!visible(el)) continue;
    if (getComputedStyle(el).cursor !== "pointer") continue;
    if (el.matches(TABBABLE_SELF) || el.closest(CONTROL)) continue;
    const parent = el.parentElement;
    if (parent && getComputedStyle(parent).cursor === "pointer") continue;
    clickable.push(`${pathOf(el)}:${short(textOf(el), 32)}`);
  }
  clickable.sort();

  /* ── Rendered text contrast ──────────────────────────────────────────── */
  const parse = (c) => {
    if (!c) return null;
    let m = c.match(/^rgba?\(([^)]+)\)$/);
    if (m) {
      const p = m[1]
        .split(/[\s,/]+/)
        .filter(Boolean)
        .map(parseFloat);
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    }
    m = c.match(/^color\(srgb ([\d.]+) ([\d.]+) ([\d.]+)(?: \/ ([\d.]+))?\)$/);
    if (m)
      return {
        r: +m[1] * 255,
        g: +m[2] * 255,
        b: +m[3] * 255,
        a: m[4] ? +m[4] : 1,
      };
    return null;
  };
  const over = (top, under) => ({
    r: top.r * top.a + under.r * (1 - top.a),
    g: top.g * top.a + under.g * (1 - top.a),
    b: top.b * top.a + under.b * (1 - top.a),
    a: 1,
  });
  const bgOf = (el) => {
    const layers = [];
    let image = false;
    for (let n = el; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.backgroundImage && cs.backgroundImage !== "none") image = true;
      const c = parse(cs.backgroundColor);
      if (c && c.a > 0) {
        layers.push(c);
        if (c.a >= 1) break;
      }
    }
    let out =
      layers.length && layers[layers.length - 1].a >= 1
        ? layers.pop()
        : { r: 255, g: 255, b: 255, a: 1 };
    while (layers.length) out = over(layers.pop(), out);
    return { bg: out, image };
  };
  const lum = ({ r, g, b }) => {
    const f = (v) =>
      (v /= 255) <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const ratio = (a, b) => {
    const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
    return (x + 0.05) / (y + 0.05);
  };
  let pairs = 0;
  let unknown = 0;
  const fails = [];
  const disabledFails = [];
  for (const el of document.body.querySelectorAll("*")) {
    const own = [...el.childNodes].some(
      (n) => n.nodeType === 3 && n.textContent.trim(),
    );
    if (!own || !visible(el)) continue;
    const cs = getComputedStyle(el);
    if (el.closest(".cc-sr-only")) continue;
    const fg0 = parse(cs.color);
    if (!fg0) {
      unknown += 1;
      continue;
    }
    const { bg, image } = bgOf(el);
    const fg = fg0.a < 1 ? over(fg0, bg) : fg0;
    const size = parseFloat(cs.fontSize);
    const weight = parseInt(cs.fontWeight, 10) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const floor = large ? 3 : 4.5;
    const r = Math.round(ratio(fg, bg) * 100) / 100;
    pairs += 1;
    if (r < floor) {
      const entry = `${pathOf(el)}|${short(textOf(el), 24)}|${r}${image ? "|img" : ""}`;
      if (el.closest(":disabled,[aria-disabled=true]"))
        disabledFails.push(entry);
      else fails.push(entry);
    }
  }
  fails.sort();
  disabledFails.sort();

  /* ── Tracked computed styles and geometry ────────────────────────────── */
  const PROPS = [
    "color",
    "background-color",
    "border-top-color",
    "font-size",
    "font-weight",
    "font-family",
    "padding",
    "border-radius",
    "text-transform",
    "height",
  ];
  const styles = {};
  const rects = {};
  for (const sel of tracked) {
    const el = [...document.querySelectorAll(sel)].find(visible);
    if (!el) {
      styles[sel] = null;
      rects[sel] = null;
      continue;
    }
    const cs = getComputedStyle(el);
    styles[sel] = Object.fromEntries(
      PROPS.map((p) => [p, cs.getPropertyValue(p)]),
    );
    const r = el.getBoundingClientRect();
    rects[sel] = [
      Math.round(r.x),
      Math.round(r.y),
      Math.round(r.width),
      Math.round(r.height),
    ].join(",");
  }

  const bodyText = textOf(document.body);
  let hash = 5381;
  for (let i = 0; i < bodyText.length; i += 1)
    hash = ((hash * 33) ^ bodyText.charCodeAt(i)) >>> 0;

  const de = document.documentElement;
  return {
    url: location.pathname + location.search,
    theme: de.getAttribute("data-theme") || "light",
    names,
    headings,
    roles,
    ariaStates,
    dialogs,
    live,
    tables,
    inline,
    classes,
    clickable,
    contrast: { pairs, unknown, fails, disabledFails },
    overflowX: de.scrollWidth > de.clientWidth + 1,
    overflowElements:
      de.scrollWidth > de.clientWidth + 1
        ? Array.from(document.querySelectorAll("*"))
            .filter((el) => {
              const rect = el.getBoundingClientRect();
              return rect.width > 0 && rect.right > de.clientWidth + 1;
            })
            .slice(0, 40)
            .map((el) => ({
              tag: el.tagName.toLowerCase(),
              className: el.getAttribute("class"),
              width: Math.round(el.getBoundingClientRect().width),
              right: Math.round(el.getBoundingClientRect().right),
              minWidth: getComputedStyle(el).minWidth,
              overflow: getComputedStyle(el).overflowX,
            }))
        : [],
    errorBoundary: /Something went wrong|Unexpected Application Error/i.test(
      bodyText,
    ),
    text: { length: bodyText.length, hash: hash.toString(16) },
    styles,
    rects,
  };
}

/** The focused element as a probe sees it: name, role and whether a ring shows. */
export function focusSnapshot() {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const cs = getComputedStyle(el);
  const ring =
    (cs.outlineStyle !== "none" && parseFloat(cs.outlineWidth) > 0) ||
    (cs.boxShadow && cs.boxShadow !== "none");
  const text = (
    el.getAttribute("aria-label") ||
    el.innerText ||
    el.textContent ||
    el.getAttribute("title") ||
    ""
  )
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 60);
  return {
    tag: el.tagName.toLowerCase(),
    role: el.getAttribute("role") || "",
    name: text,
    ring: Boolean(ring),
  };
}
