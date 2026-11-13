"use strict";
const iconAliases = {
  user: "account",
  shield: "security",
  key: "password",
  globe: "domains",
  pen: "edit",
  users: "community",
  paperclip: "attachment",
  mail: "envelope",
  x: "close",
  "arrow-up-right": "external",
  lightbulb: "lightbulb",
};
const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c],
  );
const svg = (name) => window.KagNodeCore.icon(iconAliases[name] || name);
function icons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((e) => {
    e.innerHTML = svg(e.dataset.icon);
  });
}
const state = {
  items: [],
  view: "overview",
  filter: "all",
  csrf: null,
  initialized: false,
  authMode: "unlock",
  account: null,
  preview: false,
  settings: {
    auto_lock: 15,
  },
  editId: null,
  itemType: "password",
  itemIcon: "",
  generated: "",
  serverOffset: 0,
  lastInput: Date.now(),
  lastActivity: 0,
  codesBusy: false,
  refreshBusy: false,
  unlocked: false,
  authBusy: false,
  authTransition: false,
};
const titles = {
  overview: [
    "Your vault",
    "Search your saved logins, verification codes and notes.",
  ],
  authenticators: [
    "Authenticators",
    "Your verification codes, ready when you need them.",
  ],
  passwords: ["Passwords", "Find a saved login or add a new one."],
  "backup-codes": [
    "Backup codes",
    "Recovery codes for when your usual sign-in method is unavailable.",
  ],
  notes: [
    "Secure notes",
    "Private notes, encrypted with the rest of your vault.",
  ],
  trash: [
    "Trash",
    "Restore a removed item or delete it permanently. Nothing is removed automatically.",
  ],
  clients: [
    "Apps & extensions",
    "Connect Bitwarden clients to your compatible Passwords server.",
  ],
  favorites: ["Favorites", "The accounts you reach for most."],
  generator: [
    "Password generator",
    "Create a different password for every account.",
  ],
  security: ["Security check", "Review password length, variety, and reuse."],
  settings: [
    "Vault settings",
    "Manage locking, your master password, and encrypted backups.",
  ],
};
const pagePaths = Object.fromEntries(
  Object.keys(titles).map((view) => [view, "/" + view]),
);
const pathView = (path) =>
  Object.keys(pagePaths).find(
    (view) => pagePaths[view] === path.replace(/\/$/, ""),
  );
let returnView =
  pathView(new URLSearchParams(location.search).get("next") || "") ||
  pathView(location.pathname) ||
  "overview";
function loading(label) {
  $("loading-label").textContent = label;
  $("loading").hidden = false;
}
let detailItem = null,
  generatedSequence = 0,
  clipboardSequence = 0,
  lastCodeAttempt = 0;
function toast(message, error = false) {
  const e = document.createElement("div");
  e.className = "toast" + (error ? " error" : "");
  e.setAttribute("role", error ? "alert" : "status");
  e.innerHTML =
    svg(error ? "alert" : "check-circle") + `<span>${esc(message)}</span>`;
  $("toasts").append(e);
  while ($("toasts").children.length > 2)
    $("toasts").firstElementChild.remove();
  setTimeout(() => e.remove(), error ? 6500 : 3800);
}
async function api(path, method = "GET", data) {
  const requestCsrf = state.csrf;
  const options = {
    method,
    headers: {
      "X-Requested-With": "Authentactor",
    },
    credentials: "same-origin",
    cache: "no-store",
  };
  if (method !== "GET") {
    options.headers["Content-Type"] = "application/json";
    options.headers["X-CSRF-Token"] = state.csrf || state.loginCsrf || "";
    options.body = JSON.stringify(data || {});
  }
  let response;
  try {
    response = await fetch("/api" + path, options);
  } catch {
    throw new Error(
      "Cannot reach your server. Check the connection and try again.",
    );
  }
  const payload = await response.json();
  if (!response.ok) {
    if (
      response.status === 401 &&
      !["/unlock", "/setup"].includes(path) &&
      state.unlocked &&
      requestCsrf === state.csrf &&
      !state.authTransition
    ) {
      showAuth();
      toast("Your vault has been locked.");
    }
    const err = new Error(payload.error || "Unable to complete this request.");
    err.status = response.status;
    throw err;
  }
  if (requestCsrf && requestCsrf !== state.csrf)
    throw new Error("The vault session changed. Please try again.");
  return payload;
}
function showError(id, message) {
  const element = $(id);
  if (!element) return;
  element.textContent = message;
  element.hidden = !message;
}
function closeDialogs() {
  window.KagNodeControls?.close();
  document.querySelectorAll("dialog[open]").forEach((d) => d.close());
}
function clearSensitive() {
  state.items = [];
  state.csrf = null;
  state.generated = "";
  state.itemIcon = "";
  detailItem = null;
  state.editId = null;
  $("items").replaceChildren();
  $("security-items").replaceChildren();
  $("detail-content").replaceChildren();
  $("utility-content").replaceChildren();
  $("generated-password").textContent = "";
  $("account-email").textContent = "";
  $("vault-subtitle").textContent = "";
  document.querySelector(".topbar .avatar").textContent = "?";
  $("item-form").reset();
  $("master-password").value = "";
  $("confirm-password").value = "";
  $("item-password").type = "password";
}
window.KagNodeAccountRequest = async (action = "state", data = {}) => {
  return action === "state"
    ? api("/kagnode-account")
    : api("/kagnode-account", "POST", { action, ...data });
};
let providerAttempt = "";
let providerReady = false;
window.KagNodeLoginHost = {
  state: () => ({
    issuer: state.providerIssuer,
    ready: providerReady,
    enabled: state.providerEnabled === true && !state.unlocked,
  }),
  request: async (action, data) => {
    if (action === "start") {
      const status = await api("/status");
      state.loginCsrf = status.csrf;
      state.providerEnabled = status.provider_enabled === true;
    }
    return api("/kagnode-login", "POST", { action, ...data });
  },
  complete: (result) => {
    if (!["unlock", "setup"].includes(result.continuation))
      throw new Error("Invalid vault continuation.");
    providerAttempt = result.attempt_id;
    showAuth(result.continuation);
    $("auth-email").value = result.email;
    $("auth-email").readOnly = true;
    $("provider-vault-note").textContent =
      result.continuation === "unlock"
        ? "KagNode identity confirmed. Your master password is still required to decrypt this vault."
        : "KagNode identity confirmed. Choose a master password to create your encrypted vault. KagNode cannot recover or decrypt it.";
    $("provider-vault-note").hidden = false;
    $("provider-local-login").hidden = false;
    $("auth-switch").hidden = true;
    if (!window.KagNodeLogin?.advance($("auth-form"), { focus: true }))
      $("master-password").focus();
  },
};
function showAuth(mode) {
  window.KagNodeCore?.setSession({ authenticated: false });
  const email = state.account?.email || $("auth-email").value;
  returnView = pathView(location.pathname) || returnView;
  closeDialogs();
  clearSensitive();
  state.account = null;
  state.authMode =
    mode ||
    (["/setup", "/signup"].includes(location.pathname) || !state.initialized
      ? "setup"
      : "unlock");
  const signup = state.authMode === "setup";
  state.unlocked = false;
  if (!providerAttempt) {
    $("auth-email").readOnly = false;
    $("provider-vault-note").hidden = true;
    $("provider-local-login").hidden = true;
    $("auth-switch").hidden = false;
    if (providerReady) window.KagNodeLogin?.reset($("provider-login"));
  }
  $("loading").hidden = true;
  $("dashboard").hidden = true;
  $("auth-screen").hidden = false;
  $("auth-email").value = email;
  $("auth-title").textContent = signup ? "Create an account" : "Sign in";
  $("auth-description").textContent = signup
    ? "Create a separate encrypted vault for this email."
    : "Open your vault with its master password.";
  $("auth-button").textContent = signup ? "Create account" : "Sign in";
  $("auth-switch").textContent = signup
    ? "Already have an account? Sign in"
    : "Create an account";
  $("confirm-wrap").hidden = !signup;
  $("confirm-password").required = signup;
  $("confirm-password").disabled = !signup;
  $("master-password").minLength = signup ? 12 : 1;
  $("master-password").autocomplete = signup
    ? "new-password"
    : "current-password";
  $("master-password").placeholder = signup
    ? "At least 12 characters"
    : "Your master password";
  $("master-password").type = "password";
  $("master-note").textContent = signup
    ? "This password encrypts your vault. Email cannot be used to reset it."
    : "KagNode sign-in confirms your identity. Your master password is still required to decrypt the vault.";
  $("auth-preview").hidden = !state.preview;
  $("provider-login").hidden = !state.providerEnabled;
  window.KagNodeLogin?.refresh();
  showError("auth-error", "");
  document.title = `${signup ? "Create account" : "Sign in"} · KagNode. Passwords`;
  history.replaceState(
    null,
    "",
    (signup ? "/setup" : "/unlock") +
      "?next=" +
      encodeURIComponent(pagePaths[returnView]),
  );
  $("sidebar").classList.remove("open");
  $("nav-scrim").hidden = true;
  $("mobile-menu").setAttribute("aria-expanded", "false");
}
async function showDashboard() {
  window.KagNodeCore?.setSession({
    authenticated: true,
    subject: state.account?.email || "",
    name: state.account?.email || "",
  });
  state.lastInput = Date.now();
  state.lastActivity = 0;
  state.unlocked = true;
  $("loading").hidden = true;
  $("auth-screen").hidden = true;
  $("dashboard").hidden = false;
  $("preview-banner").hidden = !state.preview;
  $("lock-label").textContent = "Sign out";
  $("sync-label").textContent = "Vault unlocked";
  $("vault-subtitle").textContent = state.account?.email || "Your vault";
  $("account-email").textContent = state.account?.email || "";
  const avatar = document.querySelector(".topbar .avatar");
  avatar.textContent = (state.account?.email || "?").charAt(0).toUpperCase();
  avatar.title = state.account?.email || "Account settings";
  avatar.setAttribute("aria-label", "Account settings");
  navigate(returnView, { history: "replace" });
  try {
    await refreshItems();
  } catch (error) {
    if (state.unlocked) {
      $("vault-load-error").hidden = false;
      toast(error.message, true);
    }
  }
}
async function refreshItems() {
  $("vault-load-error").hidden = true;
  const showSkeleton = !state.items.length;
  if (showSkeleton) {
    state.loadingItems = true;
    $("items").setAttribute("aria-busy", "true");
    $("items").innerHTML = Array.from(
      { length: 3 },
      () =>
        '<div class="skeleton-card" aria-hidden="true"><i class="skeleton-line"></i><i class="skeleton-line"></i><i class="skeleton-line"></i></div>',
    ).join("");
    $("empty").hidden = true;
  }
  try {
    {
      const data = await api("/items");
      state.items = data.items;
      state.settings = data.settings;
      state.serverOffset = data.server_time * 1000 - Date.now();
    }
  } catch (error) {
    if (showSkeleton) $("items").replaceChildren();
    throw error;
  } finally {
    state.loadingItems = false;
    $("items").removeAttribute("aria-busy");
  }
  renderStats();
  if (
    [
      "overview",
      "authenticators",
      "passwords",
      "backup-codes",
      "favorites",
      "notes",
    ].includes(state.view)
  )
    renderItems();
  if (state.view === "security") renderSecurity();
  $("auto-lock").value = String(state.settings.auto_lock);
  window.KagNodeControls?.sync();
}
function renderStats() {
  const items = state.items,
    pw = items.filter((i) => i.has_password),
    otp = items.filter((i) => i.has_totp);
  $("nav-totp-count").textContent = otp.length;
  $("nav-password-count").textContent = pw.length;
  $("nav-backup-count").textContent = items.filter(
    (i) => i.has_backup_codes,
  ).length;
  $("filter-backup").textContent = items.filter(
    (i) => i.has_backup_codes,
  ).length;
  $("security-dot").hidden = !pw.some((i) => i.strength === "weak" || i.reused);
  $("filter-all").textContent = items.length;
  $("filter-totp").textContent = otp.length;
  $("filter-password").textContent = pw.length;
  $("filter-notes").textContent = items.filter(
    (i) => !i.has_password && !i.has_totp && !i.has_backup_codes,
  ).length;
  const folder = $("folder-filter"),
    selected = folder.value;
  folder.innerHTML =
    '<option value="">All folders</option>' +
    [...new Set(items.map((i) => i.folder).filter(Boolean))]
      .sort((a, b) => a.localeCompare(b))
      .map((name) => `<option value="${esc(name)}">${esc(name)}</option>`)
      .join("");
  folder.value = [...folder.options].some((o) => o.value === selected)
    ? selected
    : "";
}
function navigate(view, options = {}) {
  if (!titles[view] || !state.unlocked) return;
  closeDialogs();
  returnView = view;
  const address = pagePaths[view];
  const current = location.pathname + location.search;
  if (options.history !== "none" && current !== address)
    history[options.history === "replace" ? "replaceState" : "pushState"](
      { view },
      "",
      address,
    );
  state.view = view;
  document
    .querySelector(".main")
    .classList.toggle("is-overview", view === "overview");
  state.filter =
    view === "authenticators"
      ? "totp"
      : view === "passwords"
        ? "password"
        : view === "backup-codes"
          ? "backup"
          : "all";
  const [title, subtitle] = titles[view];
  $("page-title").textContent = title;
  $("page-subtitle").textContent = subtitle;
  $("breadcrumb-current").textContent =
    view === "overview" ? "All items" : title;
  $("topbar-current").textContent = view === "overview" ? "All items" : title;
  document.title = `${title} · KagNode. Passwords`;
  document.querySelectorAll(".nav-item").forEach((e) => {
    const active = e.dataset.view === view;
    e.classList.toggle("active", active);
    if (active && e.closest("details")) e.closest("details").open = true;
    active
      ? e.setAttribute("aria-current", "page")
      : e.removeAttribute("aria-current");
  });
  document.querySelectorAll("a[data-view]").forEach((link) => {
    link.href = pagePaths[link.dataset.view];
  });
  const vault = [
    "overview",
    "authenticators",
    "passwords",
    "backup-codes",
    "favorites",
    "notes",
  ].includes(view);
  $("vault-view").hidden = !vault;
  $("passwords-tools").hidden = !["trash", "clients"].includes(view);
  if (["trash", "clients"].includes(view))
    renderPasswordTools().catch((e) => toast(e.message, true));
  $("generator-view").hidden = view !== "generator";
  $("security-view").hidden = view !== "security";
  $("settings-view").hidden = view !== "settings";
  $("page-actions").hidden = !vault;
  $("filters").hidden = view !== "overview";
  $("items-heading").firstChild.textContent =
    view === "overview"
      ? "All vault items "
      : view === "favorites"
        ? "Your favorites "
        : view === "backup-codes"
          ? "Your backup codes "
          : "Your " + view + " ";
  $("search").value = "";
  if (vault) renderItems();
  if (view === "generator") generate().catch((e) => toast(e.message, true));
  if (view === "security") renderSecurity();
  if (view === "settings")
    $("auto-lock").value = String(state.settings.auto_lock);
  $("sidebar").classList.remove("open");
  $("nav-scrim").hidden = true;
  $("mobile-menu").setAttribute("aria-expanded", "false");
  window.KagNodeControls?.sync();
}
function domain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}
function logo(item) {
  const color = ["orange", "blue", "purple", "dark", "green", "red"][
    [...item.name].reduce((s, c) => s + c.charCodeAt(0), 0) % 6
  ];
  return `<div class="site-logo logo-${esc(color)}">${item.icon ? `<img src="${esc(item.icon)}" alt="" loading="lazy">` : esc(item.name.charAt(0).toUpperCase())}</div>`;
}
function formatCode(code) {
  if (!code) return "··· ···";
  const mid = code.length / 2;
  return code.slice(0, mid) + " " + code.slice(mid);
}
function timer(item) {
  return `<div class="timer" data-timer="${esc(item.id)}"><svg viewBox="0 0 28 28" aria-hidden="true"><circle class="timer-track" cx="14" cy="14" r="12"/><circle class="timer-progress" cx="14" cy="14" r="12"/></svg><span>–</span></div>`;
}
function renderItems() {
  if (state.loadingItems) return;
  let items = state.items
    .filter((i) => state.view !== "favorites" || i.favorite)
    .filter(
      (i) =>
        state.view !== "notes" ||
        (!i.has_password && !i.has_totp && !i.has_backup_codes),
    )
    .filter(
      (i) =>
        state.filter === "all" ||
        (state.filter === "totp"
          ? i.has_totp
          : state.filter === "backup"
            ? i.has_backup_codes
            : state.filter === "note"
              ? !i.has_password && !i.has_totp && !i.has_backup_codes
              : i.has_password),
    );
  const folder = $("folder-filter").value;
  if (folder) items = items.filter((i) => i.folder === folder);
  const search = $("search").value.trim().toLowerCase();
  items = items.filter((i) =>
    [i.name, i.username, i.url, i.folder].some((v) =>
      String(v).toLowerCase().includes(search),
    ),
  );
  items.sort((a, b) =>
    $("sort").value === "recent"
      ? b.updated_at - a.updated_at
      : a.name.localeCompare(b.name),
  );
  $("items").innerHTML = items
    .map((i) => {
      const types = [
        i.has_password && "Password",
        i.has_totp && "Authenticator",
        i.has_backup_codes && "Backup codes",
      ].filter(Boolean);
      return `<article class="item-card vault-row" data-id="${esc(i.id)}"><div class="vault-row-identity">${logo(i)}<button class="item-title" data-action="detail" aria-label="Open ${esc(i.name)}"><strong>${esc(i.name)}</strong><small>${esc(i.username || domain(i.url) || i.folder || "Secure note")}</small></button></div><div class="vault-row-kind"><span>${esc(types.join(" · ") || "Secure note")}</span>${i.folder ? `<small>${esc(i.folder)}</small>` : ""}${i.has_backup_codes ? `<button class="backup-summary" data-action="detail">${i.backup_codes_remaining} of ${i.backup_codes_total} backup codes available</button>` : ""}</div><div class="vault-row-copy">${i.has_totp ? `<button class="code-text" data-code="${esc(i.id)}" data-action="copy-code" aria-label="Copy ${esc(i.name)} verification code">${formatCode(i.code)}</button>${timer(i)}` : i.has_password ? `<button class="icon-button" data-action="copy-password" aria-label="Copy ${esc(i.name)} password">${svg("copy")}</button>` : `<button class="icon-button" data-action="detail" aria-label="Open ${esc(i.name)} details">${svg("arrow-right")}</button>`}</div><button class="icon-button ${i.favorite ? "favorite-active" : ""}" data-action="favorite" aria-label="${i.favorite ? "Remove from" : "Add to"} favorites" aria-pressed="${i.favorite}">${svg("star")}</button></article>`;
    })
    .join("");
  $("empty").hidden = items.length > 0;
  $("items-footer").hidden = !items.length;
  $("item-count").textContent = items.length;
  $("results-label").textContent =
    `Showing ${items.length} ${items.length === 1 ? "item" : "items"}`;
  const isSearch = search.length > 0 || state.items.length > 0;
  $("empty-title").textContent = isSearch
    ? search
      ? "No matching items."
      : state.view === "favorites"
        ? "Keep your favorites close."
        : "No items in this view."
    : "Your vault is empty.";
  $("empty-description").innerHTML = search
    ? "Try another name, account, or website."
    : state.view === "favorites"
      ? "Tap the star on an item to keep it here."
      : "Use Add new item to save a login, authenticator, recovery codes or a private note.";
  document
    .querySelectorAll("[data-filter]")
    .forEach((e) =>
      e.classList.toggle("active", e.dataset.filter === state.filter),
    );
  tickTimers();
}
function tickTimers() {
  const now = (Date.now() + state.serverOffset) / 1000;
  document.querySelectorAll("[data-timer]").forEach((el) => {
    const item = state.items.find((i) => i.id === el.dataset.timer);
    if (!item) return;
    const left = Math.max(0, Math.ceil(item.expires_at - now));
    el.querySelector("span").textContent = left + "s";
    el.querySelector(".timer-progress").setAttribute(
      "stroke-dashoffset",
      String(75.4 * (1 - Math.min(1, left / item.period))),
    );
  });
  document.querySelectorAll("[data-code]").forEach((el) => {
    const item = state.items.find((i) => i.id === el.dataset.code);
    if (item) {
      el.textContent =
        item.expires_at > now ? formatCode(item.code) : "··· ···";
      el.dataset.stale = String(item.expires_at <= now);
    }
  });
}
async function refreshCodes() {
  if (state.codesBusy) return;
  state.codesBusy = true;
  lastCodeAttempt = Date.now();
  try {
    {
      const data = await api("/codes");
      state.serverOffset = data.server_time * 1000 - Date.now();
      for (const c of data.codes) {
        const i = state.items.find((i) => i.id === c.id);
        if (i) Object.assign(i, c);
      }
    }
    tickTimers();
  } catch (e) {
    if (e.status !== 401)
      toast("Codes could not refresh. Check your connection.", true);
  } finally {
    state.codesBusy = false;
  }
}
async function copy(text, label = "Copied", clear = true) {
  let successful = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      successful = true;
    } else {
      const area = document.createElement("textarea");
      area.className = "clipboard-helper";
      area.value = text;
      const previousFocus = document.activeElement;
      (document.querySelector("dialog[open]") || document.body).append(area);
      area.focus();
      area.select();
      successful = document.execCommand("copy");
      area.remove();
      previousFocus?.focus();
    }
  } catch {}
  if (!successful) {
    toast(
      "Copy unavailable in this browser. Open the item to select the value.",
      true,
    );
    return;
  }
  toast(label);
  const seq = ++clipboardSequence;
  if (clear && navigator.clipboard && window.isSecureContext) {
    setTimeout(async () => {
      if (seq !== clipboardSequence) return;
      try {
        if ((await navigator.clipboard.readText()) === text)
          await navigator.clipboard.writeText("");
      } catch {}
    }, 30000);
  }
}
async function itemAction(action, id) {
  const item = state.items.find((i) => i.id === id);
  if (!item) return;
  try {
    if (action === "favorite") {
      {
        await api("/items/" + id, "PUT", {
          favorite: !item.favorite,
        });
        item.favorite = !item.favorite;
      }
      renderItems();
    }
    if (action === "detail") await openDetail(id);
    if (action === "copy-code") {
      if (item.expires_at <= (Date.now() + state.serverOffset) / 1000) {
        await refreshCodes();
        if (item.expires_at <= (Date.now() + state.serverOffset) / 1000)
          throw new Error("Waiting for a fresh code. Try again in a moment.");
      }
      await copy(item.code, "Verification code copied");
    }
    if (action === "copy-password") {
      const data = (await api("/items/" + id)).item;
      await copy(data.password, "Password copied");
    }
  } catch (e) {
    toast(e.message, true);
  }
}
function setItemType(type) {
  state.itemType = type;
  for (const t of ["password", "totp", "both", "backup", "note"]) {
    $("type-" + t).classList.toggle("selected", type === t);
    $("type-" + t).setAttribute("aria-pressed", String(type === t));
  }
  $("password-fields").hidden = !["password", "both"].includes(type);
  $("totp-fields").hidden = !["totp", "both"].includes(type);
  $("item-password").required = ["password", "both"].includes(type);
  $("item-secret").required = ["totp", "both"].includes(type);
  $("item-backup-codes").required = type === "backup";
  $("backup-optional").hidden = type === "backup";
  $("item-notes").required = type === "note";
}
async function openItem(id = null, prefill = "") {
  closeDialogs();
  $("item-form").reset();
  $("item-password").type = "password";
  state.editId = id;
  state.itemIcon = "";
  $("item-dialog-title").textContent = id
    ? "Edit vault item"
    : "Add a new item";
  $("save-item").innerHTML =
    (id ? "Save changes" : "Save item") + svg("arrow-right");
  showError("item-error", "");
  $("item-icon-preview").textContent = "a";
  setItemType(
    state.view === "authenticators"
      ? "totp"
      : state.view === "backup-codes"
        ? "backup"
        : state.view === "notes"
          ? "note"
          : "password",
  );
  if (id) {
    try {
      const i = (await api("/items/" + id)).item;
      for (const field of [
        "name",
        "username",
        "url",
        "password",
        "secret",
        "notes",
        "folder",
        "algorithm",
        "digits",
        "period",
      ])
        $("item-" + field).value = i[field] ?? "";
      $("item-favorite").checked = i.favorite;
      state.itemIcon = i.icon;
      $("item-backup-codes").value = (i.backup_codes || [])
        .map((c) => c.code)
        .join("\n");
      setItemType(
        i.password && i.secret
          ? "both"
          : i.secret
            ? "totp"
            : i.password
              ? "password"
              : i.has_backup_codes || i.backup_codes?.length
                ? "backup"
                : "note",
      );
      renderIconPreview();
    } catch (e) {
      toast(e.message, true);
      return;
    }
  }
  if (prefill) {
    $("item-password").value = prefill;
    setItemType("password");
  }
  window.KagNodeControls?.sync();
  $("item-dialog").showModal();
}
function renderIconPreview() {
  const url = state.itemIcon;
  $("item-icon-preview").innerHTML = url
    ? `<img src="${esc(url)}" alt="Website icon">`
    : esc(
        (
          $("item-name").value ||
          domain(
            ($("item-url").value.includes("://") ? "" : "https://") +
              $("item-url").value,
          ) ||
          "a"
        )
          .charAt(0)
          .toUpperCase(),
      );
}
async function fetchItemIcon(quiet = false) {
  if (!$("item-url").value.trim()) return;
  if ($("fetch-icon").disabled) return;
  const requestedUrl = $("item-url").value.trim();
  $("fetch-icon").disabled = true;
  $("fetch-icon").textContent = "Fetching…";
  try {
    const data = await api("/icon", "POST", {
      url: requestedUrl,
    });
    if ($("item-url").value.trim() === requestedUrl && $("item-dialog").open) {
      state.itemIcon = data.icon;
      renderIconPreview();
      if (!quiet) toast("Website icon fetched");
    }
  } catch (e) {
    if (!quiet) toast(e.message, true);
  } finally {
    $("fetch-icon").disabled = false;
    $("fetch-icon").textContent = "Fetch icon";
  }
}
async function saveItem(event) {
  event.preventDefault();
  const btn = $("save-item");
  btn.disabled = true;
  showError("item-error", "");
  try {
    if (
      ["totp", "both"].includes(state.itemType) &&
      $("item-secret").value.toLowerCase().startsWith("otpauth://")
    )
      await parseSetupLink();
    const data = {};
    for (const field of [
      "name",
      "username",
      "url",
      "password",
      "secret",
      "notes",
      "folder",
      "algorithm",
      "digits",
      "period",
    ])
      data[field] = $("item-" + field).value;
    if (!["totp", "both"].includes(state.itemType)) data.secret = "";
    if (!["password", "both"].includes(state.itemType)) data.password = "";
    data.backup_codes = $("item-backup-codes").value;
    data.favorite = $("item-favorite").checked;
    data.icon = state.itemIcon;
    await api(
      state.editId ? "/items/" + state.editId : "/items",
      state.editId ? "PUT" : "POST",
      data,
    );
    $("item-form").dispatchEvent(
      new CustomEvent("kagnode:form-saved", { bubbles: true }),
    );
    $("item-dialog").close();
    toast(state.editId ? "Changes saved" : "Item added to your vault");
    await refreshItems();
  } catch (e) {
    showError("item-error", e.message);
  } finally {
    btn.disabled = false;
  }
}
async function parseSetupLink() {
  const secret = $("item-secret").value.trim();
  if (!secret.toLowerCase().startsWith("otpauth://")) return;
  const parsed = await api("/parse-totp", "POST", {
    secret,
  });
  for (const key of ["secret", "algorithm", "digits", "period"])
    $("item-" + key).value = parsed[key];
  if (!$("item-name").value) $("item-name").value = parsed.name || "";
  if (!$("item-username").value)
    $("item-username").value = parsed.username || "";
  renderIconPreview();
  window.KagNodeControls?.sync();
}
async function openDetail(id) {
  try {
    const i = (await api("/items/" + id)).item;
    detailItem = i;
    const summary = state.items.find((x) => x.id === id);
    $("detail-content").innerHTML =
      `<div class="detail-hero">${logo(summary)}<div><h2>${esc(i.name)}</h2><p>${esc(i.username || "Personal account")}</p></div><button class="icon-button close-dialog" aria-label="Close">${svg("x")}</button></div><div class="detail-body">${i.username ? detailRow("Account", i.username, "username") : ""}${i.url ? detailRow("Website", i.url, "url") : ""}${i.password ? `<div class="detail-row"><label>Password</label><div><output id="detail-password" class="secret-value">••••••••••••••••</output><button class="icon-button" id="detail-reveal" aria-label="Show password">${svg("eye")}</button><button class="icon-button" data-detail-copy="password" aria-label="Copy password">${svg("copy")}</button></div></div>` : ""}${i.secret ? `<div class="detail-row"><label>Verification code · ${esc(i.algorithm)} · ${i.period}s</label><div><button class="code-text" data-code="${esc(i.id)}" data-detail-code="${esc(i.id)}" aria-label="Copy verification code">${formatCode(summary.code)}</button><div class="code-side">${timer(summary)}</div><button class="icon-button" data-detail-code="${esc(i.id)}" aria-label="Copy verification code">${svg("copy")}</button></div></div>` : ""}${backupCodeDetails(i)}${i.notes ? `<div class="detail-row"><label>Notes</label><output>${esc(i.notes)}</output></div>` : ""}<p class="small-note">Updated ${esc(new Date(i.updated_at * 1000).toLocaleDateString(undefined, { month: "long", day: "numeric", year: "numeric" }))}</p></div><div class="modal-footer"><button class="button danger small" id="detail-delete">${svg("trash")}Delete item</button><button class="button secondary small" id="detail-edit">${svg("edit")}Edit item</button></div>`;
    $("detail-dialog").showModal();
    tickTimers();
  } catch (e) {
    toast(e.message, true);
  }
}
function backupCodeDetails(item) {
  const codes = item.backup_codes || [];
  if (!codes.length) return "";
  const available = codes.filter((c) => !c.used).length;
  return `<section class="backup-details" aria-label="Backup codes"><div class="backup-details-heading"><h3>Backup codes</h3><span>${available} of ${codes.length} available</span></div><p class="small-note">Copying does not mark a code as used. After the service accepts it, mark it here.</p><div class="backup-code-list">${codes.map((c, index) => `<div class="backup-code-row ${c.used ? "is-used" : ""}" data-backup-id="${esc(c.id)}"><span class="backup-code-number">${index + 1}</span><output class="backup-code-value" aria-label="Backup code ${index + 1}">•••• •••• ••••</output><div class="backup-code-actions"><button type="button" class="icon-button" data-backup-action="reveal" aria-label="Show backup code ${index + 1}" aria-pressed="false">${svg("eye")}</button><button type="button" class="icon-button" data-backup-action="copy" aria-label="Copy backup code ${index + 1}" ${c.used ? "disabled" : ""}>${svg("copy")}</button><button type="button" class="button secondary small backup-usage" data-backup-action="usage" aria-label="${c.used ? "Mark available" : "Mark used"} backup code ${index + 1}">${svg(c.used ? "refresh" : "check")}<span>${c.used ? "Mark available" : "Mark used"}</span></button></div><span class="backup-code-status">${c.used ? "Used" + (c.used_at ? " · " + esc(new Date(c.used_at * 1000).toLocaleDateString()) : "") : "Available"}</span></div>`).join("")}</div></section>`;
}
async function backupCodeAction(button) {
  const item = detailItem,
    row = button.closest("[data-backup-id]");
  const code = item?.backup_codes?.find((c) => c.id === row.dataset.backupId);
  if (!code) return;
  const action = button.dataset.backupAction;
  if (action === "reveal") {
    const show = button.getAttribute("aria-pressed") !== "true";
    row.querySelector("output").textContent = show
      ? code.code
      : "•••• •••• ••••";
    button.setAttribute("aria-pressed", String(show));
    const number = row.querySelector(".backup-code-number").textContent;
    button.setAttribute(
      "aria-label",
      `${show ? "Hide" : "Show"} backup code ${number}`,
    );
    button.innerHTML = svg(show ? "eye-off" : "eye");
  } else if (action === "copy" && !code.used)
    await copy(code.code, "Backup code copied; mark it used after signing in");
  else if (action === "usage") {
    button.disabled = true;
    try {
      await api(`/items/${item.id}/backup-codes/${code.id}/usage`, "POST", {
        used: !code.used,
      });
      if (detailItem?.id === item.id && $("detail-dialog").open)
        await openDetail(item.id);
      await refreshItems();
      toast(
        code.used ? "Backup code marked available" : "Backup code marked used",
      );
    } catch (error) {
      toast(error.message, true);
    } finally {
      button.disabled = false;
    }
  }
}
function detailRow(label, value, key) {
  return `<div class="detail-row"><label>${label}</label><div><output>${esc(value)}</output><button class="icon-button" data-detail-copy="${key}" aria-label="Copy ${label.toLowerCase()}">${svg("copy")}</button></div></div>`;
}
function utility(title, content, submitLabel, handler, danger = false) {
  $("utility-content").innerHTML =
    `<div class="modal-heading"><div><span class="eyebrow">YOUR PERSONAL VAULT</span><h2>${title}</h2></div><button class="icon-button close-dialog" aria-label="Close">${svg("x")}</button></div><form id="utility-form" class="utility-form">${content}<div id="utility-error" class="form-error" role="alert" hidden></div><div class="utility-actions"><button type="button" class="button secondary close-dialog">Cancel</button><button type="submit" id="utility-submit" class="button ${danger ? "danger" : "primary"}">${submitLabel}</button></div></form>`;
  $("utility-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("utility-submit").disabled = true;
    try {
      await handler();
      $("utility-dialog").close();
    } catch (err) {
      showError("utility-error", err.message);
    } finally {
      if ($("utility-submit")) $("utility-submit").disabled = false;
    }
  });
  $("utility-dialog").showModal();
}
function deleteItem() {
  const i = detailItem;
  closeDialogs();
  utility(
    "Move this item to Trash?",
    `<p>Remove <strong>${esc(i.name)}</strong> from your vault? You can restore it from Trash. It stays encrypted until you explicitly delete it permanently.</p>`,
    "Move to Trash",
    async () => {
      await api("/items/" + i.id, "DELETE");
      await refreshItems();
      toast("Item moved to Trash");
    },
    true,
  );
}
function generatorOptions() {
  return {
    length: Number($("password-length").value),
    uppercase: $("gen-uppercase").checked,
    lowercase: $("gen-lowercase").checked,
    numbers: $("gen-numbers").checked,
    symbols: $("gen-symbols").checked,
    exclude_ambiguous: $("gen-exclude").checked,
  };
}
async function generate() {
  const seq = ++generatedSequence,
    options = generatorOptions();
  const data = await api("/generate", "POST", options);
  if (seq !== generatedSequence || !state.unlocked) return;
  state.generated = data.password;
  $("generated-password").textContent = data.password;
  $("generated-strength").textContent =
    data.strength.charAt(0).toUpperCase() +
    data.strength.slice(1) +
    " password";
  document.querySelector(".strength-line").dataset.strength = data.strength;
}
function renderSecurity() {
  const pw = state.items.filter((i) => i.has_password),
    flagged = pw.filter((i) => i.strength !== "strong" || i.reused);
  $("security-title").textContent = pw.length
    ? flagged.length
      ? `${flagged.length} ${flagged.length === 1 ? "password needs" : "passwords need"} review.`
      : "No issues in these basic checks."
    : "No passwords to check yet.";
  $("security-description").textContent = pw.length
    ? `${pw.length} ${pw.length === 1 ? "password checked" : "passwords checked"} locally. Nothing is sent to an external service.`
    : "Save a password in your vault to see a local security check.";
  $("security-score").textContent = pw.length
    ? `${pw.length - flagged.length} / ${pw.length} pass basic checks`
    : "Local analysis";
  $("security-items").innerHTML = flagged
    .map(
      (i) =>
        `<div class="security-row" data-id="${esc(i.id)}">${logo(i)}<div class="security-text"><strong>${esc(i.name)}</strong><p>${esc(i.username || domain(i.url))}</p></div><span class="pill ${i.reused || i.strength === "weak" ? "weak" : "fair"}">${i.reused ? "Reused" : i.strength === "weak" ? "Weak password" : "Could be stronger"}</span><button class="button secondary small" data-security-edit="${esc(i.id)}">Review ${svg("arrow-right")}</button></div>`,
    )
    .join("");
  if (pw.length && !flagged.length)
    $("security-items").innerHTML =
      `<div class="empty-state"><div>${svg("check-circle")}</div><h3>No weak or repeated passwords found.</h3><p>Your saved passwords pass the basic length, variety, and reuse checks.</p></div>`;
}
async function backup() {
  try {
    const data = await api("/backup");
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download =
      "kagnode-authenticator-backup-" +
      new Date().toISOString().slice(0, 10) +
      ".json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Encrypted backup downloaded");
  } catch (e) {
    toast(e.message, true);
  }
}
function restore() {
  utility(
    "Restore a backup",
    `<p>Add items from a compatible encrypted backup. Your existing items are kept. Use the master password that protected the backup when it was created.</p><div class="field"><label for="backup-file">Encrypted backup file</label><input type="file" id="backup-file" accept=".json,application/json" required></div><div class="field"><label for="backup-password">Backup’s master password</label><input type="password" id="backup-password" autocomplete="off" required maxlength="1024"></div>`,
    "Restore items",
    async () => {
      const file = $("backup-file").files[0];
      if (!file || file.size > 16000000)
        throw new Error("Choose an encrypted backup smaller than 16 MB.");
      let backup;
      try {
        backup = JSON.parse(await file.text());
      } catch {
        throw new Error("This file is not a valid JSON backup.");
      }
      const result = await api("/restore", "POST", {
        backup,
        password: $("backup-password").value,
      });
      await refreshItems();
      toast(
        `${result.imported} items restored; ${result.skipped} already present.`,
      );
    },
  );
}
function changeMaster() {
  utility(
    "Change master password",
    `<p>Your vault will be re-encrypted and other sessions locked. Existing backups will still need their original password.</p><div class="field"><label for="current-master">Current master password</label><input id="current-master" type="password" autocomplete="current-password" required maxlength="1024"></div><div class="field"><label for="new-master">New master password · at least 12 characters</label><input id="new-master" type="password" autocomplete="new-password" minlength="12" maxlength="1024" required></div><div class="field"><label for="new-master-confirm">Confirm new password</label><input id="new-master-confirm" type="password" autocomplete="new-password" required maxlength="1024"></div>`,
    "Update password",
    async () => {
      if ($("new-master").value !== $("new-master-confirm").value)
        throw new Error("The new passwords do not match.");
      state.authTransition = true;
      try {
        const data = await api("/change-password", "POST", {
          current: $("current-master").value,
          password: $("new-master").value,
        });
        state.csrf = data.csrf;
        toast("Master password updated. Other sessions are now locked.");
      } finally {
        state.authTransition = false;
      }
    },
  );
}
function bind() {
  document.querySelectorAll("[data-view]").forEach((e) =>
    e.addEventListener("click", (event) => {
      if (
        e.tagName === "A" &&
        (event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey ||
          event.button)
      )
        return;
      event.preventDefault();
      navigate(e.dataset.view);
    }),
  );
  window.addEventListener("popstate", () => {
    if (!state.unlocked) {
      showAuth();
      return;
    }
    const view = pathView(location.pathname);
    navigate(view || returnView, { history: view ? "none" : "replace" });
  });
  $("retry-items").addEventListener("click", () =>
    refreshItems().catch((error) => {
      $("vault-load-error").hidden = false;
      toast(error.message, true);
    }),
  );
  document.querySelectorAll("[data-filter]").forEach((e) =>
    e.addEventListener("click", () => {
      state.filter = e.dataset.filter;
      renderItems();
    }),
  );
  $("auth-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (state.authBusy) return;
    showError("auth-error", "");
    const password = $("master-password").value;
    if (
      state.authMode === "setup" &&
      password !== $("confirm-password").value
    ) {
      showError("auth-error", "The passwords do not match.");
      return;
    }
    state.authBusy = true;
    const btn = document.querySelector(".auth-submit");
    btn.disabled = true;
    loading(
      state.authMode === "setup" ? "Creating your account…" : "Signing in…",
    );
    try {
      const data = await api(
        state.authMode === "setup" ? "/setup" : "/unlock",
        "POST",
        {
          email: $("auth-email").value,
          password,
          ...(providerAttempt ? { provider_attempt: providerAttempt } : {}),
        },
      );
      state.csrf = data.csrf;
      state.settings = data.settings;
      state.account = data.account;
      state.initialized = true;
      providerAttempt = "";
      $("auth-email").readOnly = false;
      $("provider-vault-note").hidden = true;
      $("provider-local-login").hidden = true;
      $("auth-switch").hidden = false;
      $("master-password").value = "";
      $("confirm-password").value = "";
      $("auth-form").dispatchEvent(
        new CustomEvent("kagnode:form-saved", { bubbles: true }),
      );
      await showDashboard();
    } catch (err) {
      showError("auth-error", err.message);
    } finally {
      state.authBusy = false;
      btn.disabled = false;
      $("loading").hidden = true;
    }
  });
  $("auth-switch").addEventListener("click", () =>
    showAuth(state.authMode === "setup" ? "unlock" : "setup"),
  );
  $("provider-local-login").addEventListener("click", async (event) => {
    event.preventDefault();
    const attempt = providerAttempt;
    providerAttempt = "";
    if (attempt)
      await api("/kagnode-login", "POST", {
        action: "cancel",
        attempt_id: attempt,
      }).catch(() => {});
    showAuth("unlock");
  });
  $("lock-button").addEventListener("click", async () => {
    state.authTransition = true;
    try {
      loading("Signing out…");
      await Promise.all([
        api("/lock", "POST"),
        new Promise((resolve) => setTimeout(resolve, 400)),
      ]);
      showAuth();
      toast("Vault locked");
    } catch (e) {
      toast(e.message, true);
    } finally {
      state.authTransition = false;
      $("loading").hidden = true;
    }
  });
  $("add-button").addEventListener("click", () => openItem());
  $("quick-search").addEventListener("click", openQuickSearch);
  $("search").addEventListener("input", renderItems);
  $("sort").addEventListener("change", renderItems);
  $("folder-filter").addEventListener("change", renderItems);
  $("items").addEventListener("click", (e) => {
    const button = e.target.closest("[data-action]");
    if (button)
      itemAction(button.dataset.action, button.closest("[data-id]").dataset.id);
  });
  for (const type of ["password", "totp", "both", "backup", "note"])
    $("type-" + type).addEventListener("click", () => setItemType(type));
  $("item-form").addEventListener("submit", saveItem);
  $("item-dialog").addEventListener("close", () => $("item-form").reset());
  $("item-name").addEventListener("input", renderIconPreview);
  $("item-url").addEventListener("input", () => {
    state.itemIcon = "";
    renderIconPreview();
  });
  $("item-url").addEventListener("change", () => fetchItemIcon(true));
  $("item-secret").addEventListener("change", () =>
    parseSetupLink().catch((e) => showError("item-error", e.message)),
  );
  $("fetch-icon").addEventListener("click", () => fetchItemIcon());
  $("quick-generate").addEventListener("click", async () => {
    try {
      const data = await api("/generate", "POST", {
        length: 20,
      });
      $("item-password").value = data.password;
      toast("New password generated. Save the item to keep it.");
    } catch (e) {
      toast(e.message, true);
    }
  });
  $("password-length").addEventListener("input", () => {
    $("length-value").textContent = $("password-length").value;
  });
  $("password-length").addEventListener("change", () =>
    generate().catch((e) => toast(e.message, true)),
  );
  for (const id of [
    "gen-uppercase",
    "gen-lowercase",
    "gen-numbers",
    "gen-symbols",
    "gen-exclude",
  ])
    $(id).addEventListener("change", () =>
      generate().catch((e) => toast(e.message, true)),
    );
  $("regenerate").addEventListener("click", () =>
    generate().catch((e) => toast(e.message, true)),
  );
  $("copy-generated").addEventListener("click", () => {
    if (state.generated) copy(state.generated, "Generated password copied");
  });
  $("save-generated").addEventListener("click", () => {
    if (state.generated) openItem(null, state.generated);
  });
  $("auto-lock").addEventListener("change", async () => {
    try {
      const minutes = Number($("auto-lock").value);
      await api("/settings", "PUT", {
        auto_lock: minutes,
      });
      state.settings.auto_lock = minutes;
      toast("Automatic lock updated");
    } catch (e) {
      $("auto-lock").value = String(state.settings.auto_lock);
      window.KagNodeControls?.sync();
      toast(e.message, true);
    }
  });
  $("backup").addEventListener("click", backup);
  $("restore-button").addEventListener("click", restore);
  $("change-master").addEventListener("click", changeMaster);
  $("security-items").addEventListener("click", (e) => {
    const b = e.target.closest("[data-security-edit]");
    if (b) openItem(b.dataset.securityEdit);
  });
  $("mobile-menu").addEventListener("click", () => {
    const open = $("sidebar").classList.toggle("open");
    $("nav-scrim").hidden = !open;
    $("mobile-menu").setAttribute("aria-expanded", String(open));
  });
  $("nav-scrim").addEventListener("click", () => {
    $("sidebar").classList.remove("open");
    $("nav-scrim").hidden = true;
    $("mobile-menu").setAttribute("aria-expanded", "false");
  });
  document.addEventListener("click", (e) => {
    const close = e.target.closest(".close-dialog");
    if (close) close.closest("dialog").close();
    const reveal = e.target.closest("[data-reveal]");
    if (reveal) {
      const input = $(reveal.dataset.reveal);
      input.type = input.type === "password" ? "text" : "password";
      const hidden = input.type === "password";
      reveal.setAttribute(
        "aria-label",
        (hidden ? "Show" : "Hide") + " password",
      );
      reveal.innerHTML = svg(hidden ? "eye" : "eye-off");
    }
  });
  $("detail-content").addEventListener("click", (e) => {
    const backupButton = e.target.closest("[data-backup-action]");
    if (backupButton)
      backupCodeAction(backupButton).catch((error) =>
        toast(error.message, true),
      );
    const copyBtn = e.target.closest("[data-detail-copy]");
    if (copyBtn && detailItem)
      copy(detailItem[copyBtn.dataset.detailCopy], "Copied");
    const code = e.target.closest("[data-detail-code]");
    if (code) itemAction("copy-code", code.dataset.detailCode);
    if (e.target.closest("#detail-reveal") && detailItem) {
      const hidden = $("detail-password").textContent.startsWith("••••");
      $("detail-password").textContent = hidden
        ? detailItem.password
        : "••••••••••••••••";
      $("detail-reveal").innerHTML = svg(hidden ? "eye-off" : "eye");
      $("detail-reveal").setAttribute(
        "aria-label",
        (hidden ? "Hide" : "Show") + " password",
      );
    }
    if (e.target.closest("#detail-delete")) deleteItem();
    if (e.target.closest("#detail-edit") && detailItem) openItem(detailItem.id);
  });
  $("detail-dialog").addEventListener("close", () => {
    detailItem = null;
    $("detail-content").replaceChildren();
  });
  $("utility-dialog").addEventListener("close", () => {
    if (!$("utility-dialog").open) $("utility-content").replaceChildren();
  });
  $("item-dialog").addEventListener("close", () => {
    $("item-password").value = "";
    $("item-secret").value = "";
    $("item-backup-codes").value = "";
    $("item-notes").value = "";
    state.itemIcon = "";
  });
  document.addEventListener("keydown", (e) => {
    if (
      (e.ctrlKey || e.metaKey) &&
      e.key.toLowerCase() === "k" &&
      state.unlocked
    ) {
      e.preventDefault();
      openQuickSearch();
      return;
    }
    const tag = e.target.tagName;
    if (
      e.key === "/" &&
      state.unlocked &&
      !["INPUT", "TEXTAREA", "SELECT"].includes(tag) &&
      !document.querySelector("dialog[open]") &&
      !$("vault-view").hidden
    ) {
      e.preventDefault();
      $("search").focus();
    }
    if (e.key === "Escape") {
      const wasOpen = $("sidebar").classList.contains("open");
      $("sidebar").classList.remove("open");
      $("nav-scrim").hidden = true;
      $("mobile-menu").setAttribute("aria-expanded", "false");
      if (wasOpen) $("mobile-menu").focus();
    }
  });
  for (const name of ["pointerdown", "keydown", "input"])
    document.addEventListener(
      name,
      () => {
        state.lastInput = Date.now();
      },
      {
        passive: true,
      },
    );
  window.addEventListener("pageshow", (e) => {
    if (e.persisted) location.reload();
  });
}
function openQuickSearch() {
  if (!state.unlocked) return;
  closeDialogs();
  $("utility-content").innerHTML =
    `<div class="quick-search-dialog"><div class="quick-search-heading"><div class="search-box"><span>${svg("search")}</span><input id="global-search" role="combobox" aria-label="Search all vault items" aria-autocomplete="list" aria-expanded="true" aria-controls="global-results" placeholder="Search your entire vault…" autocomplete="off"></div><button class="icon-button close-dialog" aria-label="Close search">${svg("x")}</button></div><div id="global-results" class="quick-search-results" role="listbox" aria-label="Matching vault items"></div><div class="quick-search-footer"><span id="quick-search-status" role="status">Search by name, account, or website</span><span class="quick-search-hint">↑ ↓ to select · Enter to open</span></div></div>`;
  let selected = 0;
  const select = (index) => {
    const rows = [...$("global-results").querySelectorAll("button")];
    if (!rows.length) {
      $("global-search").removeAttribute("aria-activedescendant");
      return;
    }
    selected = (index + rows.length) % rows.length;
    rows.forEach((row, i) =>
      row.setAttribute("aria-selected", String(i === selected)),
    );
    $("global-search").setAttribute("aria-activedescendant", rows[selected].id);
    rows[selected].scrollIntoView({ block: "nearest", behavior: "instant" });
  };
  const render = () => {
    const q = $("global-search").value.toLowerCase().trim();
    const found = state.items
      .filter((i) =>
        [i.name, i.username, i.url, i.folder].some((t) =>
          String(t).toLowerCase().includes(q),
        ),
      )
      .slice(0, 8);
    $("global-results").innerHTML = found.length
      ? found
          .map(
            (i, index) =>
              `<button type="button" class="quick-result" role="option" aria-selected="false" id="global-result-${index}" data-search-id="${esc(i.id)}">${logo(i)}<span class="quick-result-copy"><strong>${esc(i.name)}</strong><small>${esc(i.username || domain(i.url) || "Personal account")}</small></span>${svg("arrow-right")}</button>`,
          )
          .join("")
      : '<div class="no-search-results"><strong>No matching items</strong><span>Try another name, account, or website.</span></div>';
    $("global-search").setAttribute("aria-expanded", String(found.length > 0));
    $("quick-search-status").textContent = found.length
      ? found.length === 8
        ? "Showing up to 8 matches"
        : found.length + " matching items"
      : "No matches";
    select(0);
  };
  $("global-search").addEventListener("input", render);
  $("global-results").addEventListener("click", (e) => {
    const b = e.target.closest("[data-search-id]");
    if (b) {
      $("utility-dialog").close();
      openDetail(b.dataset.searchId);
    }
  });
  $("global-search").addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      select(selected + (e.key === "ArrowDown" ? 1 : -1));
    }
    if (e.key === "Enter") {
      e.preventDefault();
      $("global-results").querySelector('[aria-selected="true"]')?.click();
    }
  });
  render();
  $("utility-dialog").showModal();
  $("global-search").focus();
}
async function heartbeat() {
  if (!state.unlocked) return;
  if (Date.now() - state.lastInput >= state.settings.auto_lock * 60000) {
    state.authTransition = true;
    try {
      await api("/lock", "POST");
    } catch {}
    showAuth();
    state.authTransition = false;
    toast("Vault automatically locked after inactivity.");
    return;
  }
  tickTimers();
  const now = (Date.now() + state.serverOffset) / 1000;
  if (
    state.items.some((i) => i.has_totp && i.expires_at <= now) &&
    Date.now() - lastCodeAttempt > 3000
  )
    await refreshCodes();
  if (
    state.lastInput > state.lastActivity &&
    Date.now() - state.lastActivity > 30000
  ) {
    state.lastActivity = Date.now();
    try {
      await api("/activity", "POST");
    } catch (e) {
      if (e.status !== 401) state.lastActivity = Date.now();
    }
  }
}
async function boot() {
  icons();
  window.KagNodeControls?.enhance();
  bind();
  try {
    const data = await api("/status");
    state.initialized = data.initialized;
    state.preview = data.preview;
    state.providerIssuer = data.provider_issuer;
    state.providerEnabled = data.provider_enabled === true;
    state.loginCsrf = data.unlocked ? null : data.csrf;
    state.account = data.account;
    state.csrf = data.csrf;
    state.settings = data.settings || {
      auto_lock: 15,
    };
    if (data.unlocked) await showDashboard();
    else showAuth();
    providerReady = true;
    window.KagNodeLogin?.refresh();
  } catch (e) {
    $("loading-label").textContent = e.message;
    $("loading").querySelector(".loading-dots").hidden = true;
    $("loading").querySelector(".loading-strip").hidden = true;
    $("loading-retry").hidden = false;
    $("loading-retry").addEventListener("click", () => location.reload(), {
      once: true,
    });
  }
  setInterval(heartbeat, 1000);
}
boot();
async function renderPasswordTools() {
  const view = state.view;
  const panel = $("passwords-tools");
  panel.textContent = "Loading…";
  if (view === "trash") {
    const { items } = await api("/trash");
    if (state.view !== view) return;
    panel.innerHTML = `<div class="panel settings-panel"><h2>Recently removed</h2><p>Items stay here until you restore them or permanently delete them.</p><div class="trash-items">${items.length ? items.map((i) => `<article class="setting-row"><div><strong>${esc(i.name)}</strong><p>${esc(i.folder || "No folder")} · Removed ${esc(new Date(i.deleted_at * 1000).toLocaleDateString())}</p></div><div class="passwords-actions"><button class="button secondary small" data-restore="${esc(i.id)}">Restore</button><button class="button danger small" data-purge="${esc(i.id)}">Delete permanently</button></div></article>`).join("") : '<p class="small-note">Trash is empty.</p>'}</div></div>`;
    panel.querySelectorAll("[data-restore]").forEach((button) =>
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          await api(`/trash/${button.dataset.restore}/restore`, "POST", {});
          await refreshItems();
          await renderPasswordTools();
          toast("Item restored");
        } catch (e) {
          toast(e.message, true);
          button.disabled = false;
        }
      }),
    );
    panel.querySelectorAll("[data-purge]").forEach((button) =>
      button.addEventListener("click", () => {
        const item = items.find((i) => i.id === button.dataset.purge);
        utility(
          "Delete permanently?",
          `<p>This removes <strong>${esc(item.name)}</strong> from the current vault. Existing backups may still contain it.</p><label for="purge-name">Type the item name</label><input id="purge-name" autocomplete="off" required maxlength="100">`,
          "Delete permanently",
          async () => {
            await api(`/trash/${item.id}/purge`, "POST", {
              confirm: $("purge-name").value,
            });
            await renderPasswordTools();
            toast("Item permanently deleted");
          },
          true,
        );
      }),
    );
  } else {
    const config = await api("/clients");
    if (state.view !== view) return;
    panel.innerHTML = `<div class="panel settings-panel"><span class="eyebrow">BITWARDEN CLIENTS</span><h2>Connect your devices</h2><p>The compatible service uses Vaultwarden. Your current KagNode vault stays separate and keeps working.</p>${config.configured ? `<div class="setting-row"><div><strong>Self-hosted server URL</strong><p><code>${esc(config.server)}</code></p></div><button class="button secondary small" id="copy-client-server">Copy URL</button></div><p>In the Bitwarden app or extension, choose <strong>Self-hosted</strong>, enter this URL, and sign in with your account on that server.</p><a class="button primary" href="${esc(config.server)}" target="_blank" rel="noopener noreferrer">Open compatible vault ${svg("arrow-up-right")}</a>` : '<div class="notice">The compatible vault has not been connected. Ask your server administrator to enable access for Bitwarden apps and extensions.</div>'}</div><div class="panel settings-panel"><h2>Transfer your existing items</h2><p>Export a Bitwarden JSON file, then import it in the compatible web vault. Passwords, authenticator keys, folders, and notes are included. Backup codes become notes with their used status. Trash is excluded. Nothing is removed from this vault.</p><p class="small-note">This export contains readable passwords. Import it privately, verify your items, then remove the export from your Downloads and Trash.</p><button class="button secondary" id="export-bitwarden">Export for Bitwarden</button></div>`;
    $("copy-client-server")?.addEventListener("click", () =>
      copy(config.server, "Server URL copied"),
    );
    $("export-bitwarden").addEventListener("click", () => {
      utility(
        "Export readable vault data",
        '<p>This file contains passwords and authenticator secrets without encryption. Only continue on your private device.</p><label for="export-password">Master password</label><input type="password" id="export-password" autocomplete="current-password" required maxlength="1024">',
        "Export unencrypted JSON",
        async () => {
          const data = await api("/export/bitwarden", "POST", {
            password: $("export-password").value,
            confirm: "unencrypted-export",
          });
          $("export-password").value = "";
          const link = document.createElement("a"),
            url = URL.createObjectURL(
              new Blob([JSON.stringify(data, null, 2)], {
                type: "application/json",
              }),
            );
          link.href = url;
          link.download = "kagnode-passwords-bitwarden.json";
          document.body.append(link);
          link.click();
          link.remove();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
          toast("Export downloaded. Delete it after verifying the import.");
        },
        true,
      );
    });
  }
}
