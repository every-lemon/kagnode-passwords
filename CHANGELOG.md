# 5.0.0

- Use the canonical Core 5 login frame, fields, provider flow and action icons.
- Keep theme selection in account/settings; signed-out pages follow the system theme.
- Preserve local credentials, explicit account linking, permissions and data compatibility.
- Publish checked source/data assets with existing package identities and paths.

# 0.6.0-beta.2

- Use the locally served shared Core login frame with explicit KagNode confirmation and bounded, browser-bound sign-in attempts.
- Refresh newly consented verified contact email alongside name and photo; preserve local policy, roles and offline sign-in.
- Passwords offers vault initialization for a new verified KagNode subject because local signup is enabled. Choose a new master password explicitly. Existing linked vaults still require their master password to decrypt; KagNode identity does not contain a vault key or provide password recovery. An existing local email collision requires signing in locally and explicitly linking that account.
- Web/source preview only; no native service or hardware qualification is implied.

# 0.6.0-beta.1 — KagNode Passwords preview

## Update recovery status preview

Show recovery details and metadata filenames in local administration. Suppress unsafe update actions, distinguish live operations from stale progress, preserve native-adapter guidance and clear repaired-cache warnings after a new release check.

## Account link recovery preview

Resume pending profile links after reload, provide attempt-scoped cancellation and visible retry controls, and ignore late browser responses. Retain failed cleanup of issued profile tokens for administrator retry. Preserve local sign-in, permissions and existing data.

## Declared Core binding preview

Document the pinned Core baseline explicitly for new server bindings and the reviewed application-upgrade workflow. Existing application data and stable release selections remain unchanged.

## Shared loading spinner preview

Use KagNode Core 1.0.5 for the shared split-orbit loading mark, with reduced-motion support and existing status/recovery controls retained. This changes web presentation without resetting data or provisioning native services.

## Core integration preview

Shared local UI components, manual animated navigation, natural scrolling rails and icon account menus. Added separate appearance-only account connections and signed UI patch controls. Existing storage, native services and prior release records are retained.

## 0.6.0-beta.1 packaging.2

- Renamed the GitHub repository to kagnode-passwords and updated source/download links.
- Preserved legacy package identities, account client IDs and existing vault storage paths.

- Rename the interface while retaining existing encrypted data, identities and backup format.
- Add secure notes, folder labels and recoverable Trash with explicit permanent removal.
- Add a password-confirmed Bitwarden JSON export and Apps & extensions setup page.
- Integrate optional local-administrator update controls through KagNode CLI.
- Support an independently configured Vaultwarden engine; actual extension/mobile
  sign-in needs an HTTPS installation check. Existing vaults are not migrated automatically.

# 0.5.0

- Shared KagNode product styling, mobile controls, and persistent product branding.
- Prebuilt, fingerprinted UI assets with minified aliases and no source maps.
- Existing account data, credentials, and API behavior are retained.

# 0.4.1

- Refuse signup at the session limit before saving an account.
- Reject malformed CSRF and encrypted-backup fields without server errors.
- Existing account passwords, vault ciphertext, and backup format remain compatible.

# Changes

## 0.4.0 — source preview

- Added email signup/sign-in with separate encrypted vaults, settings and sessions.
- Added an explicit-owner migration that retains the database, original ciphertext and password.
- Scoped item actions, codes, backups, restore, password changes and automatic locking to each account.
- Added account switching, clearer sign-in text and multi-account/migration tests.

## 0.3.0 — source preview

- Added encrypted backup codes, standalone or attached to existing items, and a dedicated `/backup-codes` route.
- Added per-code reveal/copy, explicit Mark used and Mark available controls, usage dates and remaining counts.
- Preserved code-use history on edits, encrypted backups, password rotation and restarts; retained older vault/backup compatibility.
- Added validation, authorization, encryption, persistence and browser workflow checks.

## 0.2.0 — source preview

- Added KagNode branding, dark/light themes, responsive navigation and custom choice controls.
- Added individual routes, authenticated deep links, history navigation and local unlock return paths.
- Added vault-loading skeletons, error recovery, a centered logo loader and the top progress strip.
- Added explicit single-proxy HTTPS origin support and route/proxy/browser regression checks.
- Retained vault encryption, saved-data location, session protections and encrypted backup compatibility.

## 0.1.0 — original local preview

- Authentactor single-owner vault, TOTP codes, password storage, generator, encrypted backup/restore and master-password rotation.

## Account profile integration preview

Added optional KagNode Account display-name/photo linking, local administrator disable controls and private credential storage. Existing local account authentication and data remain independent.
