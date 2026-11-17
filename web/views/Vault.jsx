// Secrets / Vault view — list $ANSIBLE_VAULT-encrypted files in the
// active server's workDir, unlock them with a caller-supplied
// password, and edit + re-encrypt in place. The password is held only
// in local component state during the unlock/save flow; it is never
// sent to the browser storage, never logged server-side, and never
// written to the remote filesystem (pipes + bash process substitution
// keep it in memory).

const { useState: useStateV, useEffect: useEffectV } = React;

function VaultView() {
  const [files, setFiles] = useStateV([]);
  const [workDir, setWorkDir] = useStateV('');
  const [loading, setLoading] = useStateV(false);
  const [error, setError] = useStateV('');
  const [selected, setSelected] = useStateV(null); // { path, name, ... }
  const [newOpen, setNewOpen] = useStateV(false);
  const [openPathOpen, setOpenPathOpen] = useStateV(false);

  const reload = async () => {
    if (!globalThis.AnsbuiAPI) return;
    setLoading(true); setError('');
    try {
      const res = await globalThis.AnsbuiAPI.listVaultFiles();
      setFiles(res.files || []);
      setWorkDir(res.workDir || '');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffectV(() => { void reload(); }, []);

  const subtitle = buildSubtitle(loading, files.length, workDir);

  return (
    <div className="view view-vault">
      <div className="view-head">
        <div>
          <h1 className="view-title">Secrets</h1>
          <div className="view-sub mute">{subtitle}</div>
        </div>
        <div className="view-actions">
          <button type="button" className="btn small" onClick={reload} disabled={loading}>
            <Icon name="refresh" size={12}/> Reload
          </button>
          <button type="button" className="btn small" onClick={() => setOpenPathOpen(true)}>
            <Icon name="search" size={12}/> Open by path…
          </button>
          <button type="button" className="btn primary small" onClick={() => setNewOpen(true)}>
            <Icon name="plus" size={12}/> New vault file…
          </button>
        </div>
      </div>

      {error && <div className="cm-error mono">{error}</div>}

      <div className="vault-grid">
        {files.length === 0 && !loading && (
          <EmptyVaultHint workDir={workDir} onOpenByPath={() => setOpenPathOpen(true)}/>
        )}
        {files.map(f => (
          <button
            type="button"
            key={f.path}
            className="card vault-tile"
            onClick={() => setSelected(f)}
          >
            <div className="vault-tile-head">
              <Icon name="vault" size={14}/>
              <span className="mono" style={{ fontWeight: 550 }}>{f.name}</span>
            </div>
            <div className="mute mono" style={{ fontSize: 11, marginTop: 4 }}>{f.path}</div>
            <div className="vault-tile-meta">
              <span className={`mini-tag mono ${f.kind === 'inline' ? 'warn' : ''}`}>
                {f.kind === 'inline' ? 'inline values' : 'whole-file'}
              </span>
              {f.vaultId && <span className="mini-tag mono">id: {f.vaultId}</span>}
              <span className="mini-tag mono">{formatBytes(f.size || 0)}</span>
            </div>
          </button>
        ))}
      </div>

      <VaultUnlockDialog
        open={selected != null}
        file={selected}
        onClose={() => setSelected(null)}
      />
      <VaultNewDialog
        open={newOpen}
        onClose={() => setNewOpen(false)}
        onCreated={() => { setNewOpen(false); void reload(); }}
      />
      <VaultOpenByPathDialog
        open={openPathOpen}
        workDir={workDir}
        onClose={() => setOpenPathOpen(false)}
        onOpen={(path) => {
          setOpenPathOpen(false);
          setSelected({ path, name: path.split('/').pop() || path });
        }}
      />
    </div>
  );
}

// EmptyVaultHint points at the real workDir so the operator can paste
// the exact path into their ansible-vault command, and offers an
// inline shortcut to open a file the scanner didn't pick up.
const HINT_CODE_STYLE = {
  background: 'var(--bg-inset)',
  border: '1px solid var(--line-soft)',
  borderRadius: 'var(--r-2)',
  padding: '8px 10px',
  margin: '6px 0',
  fontSize: 12,
  color: 'var(--text-2)',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all'
};

function EmptyVaultHint({ workDir, onOpenByPath }) {
  return (
    <div className="mute" style={{ padding: 24, fontSize: 12.5, lineHeight: 1.7 }}>
      <div>
        No vault-encrypted files under the active server's workDir.
      </div>
      {workDir && (
        <div style={{ marginTop: 8 }}>
          Scanner looked at <span className="mono" style={{ color: 'var(--text-2)' }}>{workDir}</span> and every subdirectory.
          Ansible supports two common layouts — use whichever matches your repo:
          <pre className="code-block" style={HINT_CODE_STYLE}>{`# inventory-dir layout (scoped per-inventory)
cd ${workDir}
ansible-vault create inventory/group_vars/all/vault.yml

# top-level layout (scoped per-repo)
ansible-vault create group_vars/all/vault.yml`}</pre>
        </div>
      )}
      <div style={{ marginTop: 6 }}>
        Or <button type="button" className="btn ghost small" onClick={onOpenByPath}>open an existing file by path</button> if it lives outside the scan (symlinked, custom header, etc.).
      </div>
    </div>
  );
}

function buildSubtitle(loading, count, workDir) {
  if (loading) return 'Scanning workDir…';
  const suffix = workDir ? ` under ${workDir}` : '';
  return `${count} vault-encrypted ${pluralise('file', count)} found${suffix}.`;
}

function pluralise(noun, n) {
  return n === 1 ? noun : `${noun}s`;
}

function unlockDialogSubtitle({ file, inlineKind, unlocked }) {
  if (inlineKind) {
    return `${file.path} — per-value !vault | encryption. Each key is encrypted independently.`;
  }
  if (unlocked) return `Unlocked · ${file.path}`;
  return `Enter the vault password to decrypt ${file.path}.`;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// ---------- Unlock + edit dialog ----------

function VaultUnlockDialog({ open, file, onClose }) {
  const [password, setPassword] = useStateV('');
  const [plaintext, setPlaintext] = useStateV(null);
  const [draft, setDraft] = useStateV('');
  const [editing, setEditing] = useStateV(false);
  const [busy, setBusy] = useStateV(false);
  const [error, setError] = useStateV('');
  const inlineKind = file?.kind === 'inline';

  useEffectV(() => {
    if (!open) {
      // Clear everything on close so a stale password / plaintext
      // doesn't linger in state for another file.
      setPassword('');
      setPlaintext(null);
      setDraft('');
      setEditing(false);
      setError('');
      setBusy(false);
    }
  }, [open]);

  const unlock = async () => {
    if (!file || !password) { setError('Password is required.'); return; }
    setBusy(true); setError('');
    try {
      const res = await globalThis.AnsbuiAPI.viewVault(file.path, password);
      setPlaintext(res.plaintext || '');
      setDraft(res.plaintext || '');
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const save = async () => {
    if (!file || !password) { setError('Password is required.'); return; }
    setBusy(true); setError('');
    try {
      await globalThis.AnsbuiAPI.writeVault(file.path, password, draft);
      setPlaintext(draft);
      setEditing(false);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  if (!file) return null;
  const unlocked = plaintext != null;
  const subtitle = unlockDialogSubtitle({ file, inlineKind, unlocked });

  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title={file.name}
      subtitle={subtitle}
      width="min(820px, 94vw)"
      maxHeight="86vh"
    >
      {error && <div className="cm-error mono">{error}</div>}

      {inlineKind && <InlineVaultEditor file={file} onClose={onClose}/>}

      {!inlineKind && !unlocked && (
        <form onSubmit={(e) => { e.preventDefault(); void unlock(); }}>
          <label htmlFor="vault-pw" className="cm-field-label">Vault password</label>
          <input
            id="vault-pw"
            type="password"
            className="input mono"
            data-autofocus
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="•••••••"
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button type="submit" className="btn primary small" disabled={busy || !password}>
              <Icon name="key" size={12}/> {busy ? 'Unlocking…' : 'Unlock'}
            </button>
            <button type="button" className="btn small" disabled={busy} onClick={onClose}>Cancel</button>
          </div>
        </form>
      )}

      {!inlineKind && unlocked && (
        <>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
            {editing ? (
              <>
                <button type="button" className="btn primary small" disabled={busy} onClick={save}>
                  <Icon name="check" size={12}/> {busy ? 'Saving…' : 'Save + re-encrypt'}
                </button>
                <button type="button" className="btn small" disabled={busy} onClick={() => { setDraft(plaintext); setEditing(false); }}>
                  Cancel
                </button>
              </>
            ) : (
              <>
                <button type="button" className="btn small" onClick={() => setEditing(true)}>
                  <Icon name="code" size={12}/> Edit
                </button>
                <button type="button" className="btn ghost small" onClick={() => copyToClipboard(plaintext)}>
                  Copy
                </button>
              </>
            )}
            <span className="mute mono" style={{ marginLeft: 'auto', fontSize: 11 }}>
              {draft.split('\n').length} lines · {draft.length} chars
            </span>
          </div>
          <textarea
            className="yaml-textarea"
            spellCheck="false"
            style={{ minHeight: 360 }}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            readOnly={!editing}
          />
          <div className="mute" style={{ fontSize: 11.5, marginTop: 8 }}>
            The password stays in memory for this dialog only — it's dropped when you close.
          </div>
        </>
      )}
    </globalThis.AnsbuiCenterDialog>
  );
}

// ---------- Inline-vault editor ----------
//
// An inline vault file is plain YAML with `!vault |` blocks for the
// values that need to stay encrypted. ansibui treats those blocks as
// individually addressable: list them by name, decrypt one at a time
// to view, and re-encrypt to rotate or insert. Comments, cleartext
// keys, and overall file structure are preserved across edits because
// the patcher only touches the lines belonging to the targeted block.

function InlineVaultEditor({ file, onClose }) {
  const [keys, setKeys] = useStateV([]);
  const [loading, setLoading] = useStateV(false);
  const [error, setError] = useStateV('');
  // active is null (list view), { mode: 'add' }, or { mode: 'edit', name }.
  const [active, setActive] = useStateV(null);

  const reload = async () => {
    if (!globalThis.AnsbuiAPI) return;
    setLoading(true); setError('');
    try {
      const res = await globalThis.AnsbuiAPI.listInlineVaultKeys(file.path);
      setKeys(res.keys || []);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffectV(() => { void reload(); }, [file?.path]);

  if (active) {
    return (
      <InlineVaultRowEditor
        file={file}
        mode={active.mode}
        existingName={active.name || ''}
        onClose={() => setActive(null)}
        onSaved={() => { setActive(null); void reload(); }}
      />
    );
  }

  return (
    <div>
      {error && <div className="cm-error mono">{error}</div>}
      <div className="mute" style={{ fontSize: 12.5, lineHeight: 1.6, marginBottom: 12 }}>
        Each key is encrypted independently with <span className="mono">ansible-vault encrypt_string</span>. Adding a new value or rotating an existing one only touches that key&rsquo;s block — comments and cleartext keys elsewhere in the file are left untouched.
      </div>
      {loading && <div className="mute mono" style={{ fontSize: 12 }}>Listing keys…</div>}
      {!loading && keys.length === 0 && (
        <div className="mute" style={{ fontSize: 12.5, marginBottom: 12 }}>
          No <span className="mono">!vault |</span> blocks in this file yet. Use <b>Add encrypted value</b> below to create the first one.
        </div>
      )}
      {keys.length > 0 && (
        <div style={{ display: 'grid', gap: 6, marginBottom: 12 }}>
          {keys.map(k => (
            <button
              key={k.name}
              type="button"
              className="card"
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', textAlign: 'left' }}
              onClick={() => setActive({ mode: 'edit', name: k.name })}
            >
              <span className="mono" style={{ fontWeight: 550 }}>{k.name}</span>
              <span className="mute mono" style={{ fontSize: 11 }}>
                lines {k.startLine}–{k.endLine} · click to decrypt + edit
              </span>
            </button>
          ))}
        </div>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <button type="button" className="btn primary small" onClick={() => setActive({ mode: 'add' })}>
          <Icon name="plus" size={12}/> Add encrypted value
        </button>
        <button type="button" className="btn small" onClick={reload} disabled={loading}>
          <Icon name="refresh" size={12}/> Reload
        </button>
        <button type="button" className="btn small" style={{ marginLeft: 'auto' }} onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}

// InlineVaultRowEditor handles both the "add new" and "rotate existing"
// flows. For rotation it first prompts for the password, decrypts the
// current value, and shows it editable; for add it shows name+value+
// password fields up front. Save calls upsertInlineVault which the
// backend turns into a single ansible-vault encrypt_string + atomic
// in-place rewrite of the file.
function InlineVaultRowEditor({ file, mode, existingName, onClose, onSaved }) {
  const isAdd = mode === 'add';
  const [name, setName] = useStateV(existingName);
  const [password, setPassword] = useStateV('');
  const [value, setValue] = useStateV('');
  const [decrypted, setDecrypted] = useStateV(isAdd); // skip the decrypt step for adds
  const [busy, setBusy] = useStateV(false);
  const [error, setError] = useStateV('');

  useEffectV(() => {
    setName(existingName);
    setPassword('');
    setValue('');
    setDecrypted(isAdd);
    setError('');
    setBusy(false);
  }, [existingName, isAdd]);

  const decrypt = async () => {
    if (!password) { setError('Password is required.'); return; }
    setBusy(true); setError('');
    try {
      const res = await globalThis.AnsbuiAPI.decryptInlineVault(file.path, name, password);
      setValue(res.plaintext || '');
      setDecrypted(true);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const save = async () => {
    if (!name) { setError('Name is required.'); return; }
    if (!password) { setError('Password is required.'); return; }
    if (!/^[A-Za-z_]\w*$/.test(name)) {
      setError('Name must be a valid ansible variable (letters, digits, underscore; no leading digit).');
      return;
    }
    setBusy(true); setError('');
    try {
      await globalThis.AnsbuiAPI.upsertInlineVault(file.path, name, value, password);
      onSaved?.();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  // Focus: this editor replaces the key list inside a dialog that is
  // already open, and the key or Add button that had focus goes away
  // with the list. Focus moves to the first field to fill in: the name
  // of a new variable, or the password for an existing one. The fields
  // mount into an open dialog, so React's autoFocus works here (it does
  // not for a field present when the dialog opens; see useDialog).
  return (
    <div>
      <div className="mute" style={{ fontSize: 12.5, marginBottom: 10 }}>
        {isAdd
          ? <>Adding a new <span className="mono">!vault |</span> block. The password is also used to encrypt subsequent values; existing blocks aren&rsquo;t re-keyed.</>
          : <>Rotating <span className="mono">{existingName}</span>. The current ciphertext is decrypted with the supplied password, the value you save is re-encrypted with the same password.</>}
      </div>

      {error && <div className="cm-error mono">{error}</div>}

      <label htmlFor="ive-name" className="cm-field-label">Variable name</label>
      <input
        id="ive-name"
        className="input mono"
        value={name}
        onChange={(e) => setName(e.target.value)}
        readOnly={!isAdd}
        placeholder="db_password"
        autoFocus={isAdd} // NOSONAR(S9379): deliberate, see "Focus" above
      />

      <label htmlFor="ive-pw" className="cm-field-label" style={{ marginTop: 10 }}>Vault password</label>
      <input
        id="ive-pw"
        className="input mono"
        type="password"
        autoComplete="new-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        autoFocus={!isAdd} // NOSONAR(S9379): deliberate, see "Focus" above
      />

      {!decrypted && (
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button type="button" className="btn primary small" disabled={busy || !password} onClick={decrypt}>
            <Icon name="key" size={12}/> {busy ? 'Decrypting…' : 'Decrypt'}
          </button>
          <button type="button" className="btn small" onClick={onClose}>Cancel</button>
        </div>
      )}

      {decrypted && (() => {
        let saveLabel;
        if (busy) saveLabel = 'Saving…';
        else if (isAdd) saveLabel = 'Encrypt + add';
        else saveLabel = 'Re-encrypt + save';
        return (
        <>
          <label htmlFor="ive-value" className="cm-field-label" style={{ marginTop: 10 }}>
            {isAdd ? 'Plaintext value' : 'Plaintext value (decrypted — edit and save to re-encrypt)'}
          </label>
          <textarea
            id="ive-value"
            className="yaml-textarea"
            spellCheck="false"
            style={{ minHeight: 140 }}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={isAdd ? 'secret-value' : ''}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button type="button" className="btn primary small" disabled={busy} onClick={save}>
              <Icon name="check" size={12}/> {saveLabel}
            </button>
            <button type="button" className="btn small" disabled={busy} onClick={onClose}>Cancel</button>
          </div>
          <div className="mute" style={{ fontSize: 11.5, marginTop: 8 }}>
            Plaintext stays in this dialog only. It&rsquo;s dropped on close and never sent back to the server unencrypted.
          </div>
        </>
        );
      })()}
    </div>
  );
}

// ---------- New vault file dialog ----------

function VaultNewDialog({ open, onClose, onCreated }) {
  const [path, setPath] = useStateV('');
  const [password, setPassword] = useStateV('');
  const [confirm, setConfirm] = useStateV('');
  const [content, setContent] = useStateV('');
  const [busy, setBusy] = useStateV(false);
  const [error, setError] = useStateV('');

  useEffectV(() => {
    if (!open) { setPath(''); setPassword(''); setConfirm(''); setContent(''); setError(''); setBusy(false); }
  }, [open]);

  const submit = async () => {
    setError('');
    if (!path.trim()) { setError('Target path is required.'); return; }
    if (!password) { setError('Password is required.'); return; }
    if (password !== confirm) { setError('Passwords do not match.'); return; }
    setBusy(true);
    try {
      await globalThis.AnsbuiAPI.writeVault(path.trim(), password, content);
      onCreated?.(path.trim());
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title="New vault file"
      subtitle="Creates a fresh $ANSIBLE_VAULT-encrypted file under the server's workDir."
      width="min(720px, 94vw)"
    >
      {error && <div className="cm-error mono">{error}</div>}

      <label htmlFor="vault-new-path" className="cm-field-label">Path (relative to workDir)</label>
      <input
        id="vault-new-path"
        className="input mono"
        value={path}
        onChange={(e) => setPath(e.target.value)}
        placeholder="group_vars/prod.yml"
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 10 }}>
        <div>
          <label htmlFor="vault-new-pw" className="cm-field-label">Vault password</label>
          <input
            id="vault-new-pw"
            type="password"
            autoComplete="new-password"
            className="input mono"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="vault-new-pw2" className="cm-field-label">Confirm password</label>
          <input
            id="vault-new-pw2"
            type="password"
            autoComplete="new-password"
            className="input mono"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
      </div>

      <label htmlFor="vault-new-body" className="cm-field-label" style={{ marginTop: 10 }}>Content (plaintext YAML)</label>
      <textarea
        id="vault-new-body"
        className="yaml-textarea"
        spellCheck="false"
        style={{ minHeight: 220 }}
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder={'---\ndb_password: hunter2'}
      />

      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        <button type="button" className="btn primary small" disabled={busy} onClick={submit}>
          <Icon name="check" size={12}/> {busy ? 'Encrypting…' : 'Create + encrypt'}
        </button>
        <button type="button" className="btn small" disabled={busy} onClick={onClose}>Cancel</button>
      </div>
    </globalThis.AnsbuiCenterDialog>
  );
}

// VaultOpenByPathDialog lets the operator unlock a file the scanner
// missed. The submitted path is still resolved relative to workDir
// on the backend (validateRelPath blocks '..' traversal), so this
// doesn't give the UI any new reach into the remote filesystem — it
// just widens the set of already-reachable paths a user can target.
function VaultOpenByPathDialog({ open, workDir, onClose, onOpen }) {
  const [path, setPath] = useStateV('');

  useEffectV(() => { if (!open) setPath(''); }, [open]);

  const submit = () => {
    const trimmed = path.trim().replace(/^\/+/, '');
    if (!trimmed) return;
    onOpen(trimmed);
  };

  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title="Open vault file by path"
      subtitle={workDir ? `Relative to ${workDir}.` : 'Relative to the active server\'s workDir.'}
    >
      <form onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <label htmlFor="vault-openpath" className="cm-field-label">Path</label>
        <input
          id="vault-openpath"
          className="input mono"
          data-autofocus
          placeholder="group_vars/prod/vault.yml"
          value={path}
          onChange={(e) => setPath(e.target.value)}
        />
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button type="submit" className="btn primary small" disabled={!path.trim()}>
            <Icon name="key" size={12}/> Open
          </button>
          <button type="button" className="btn small" onClick={onClose}>Cancel</button>
        </div>
        <div className="mute" style={{ fontSize: 11.5, marginTop: 10 }}>
          You'll be prompted for the vault password on the next screen. The path must live inside the server's workDir — '..' traversal is rejected by the backend.
        </div>
      </form>
    </globalThis.AnsbuiCenterDialog>
  );
}

async function copyToClipboard(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // ignore — some browsers block clipboard from insecure origins
  }
}

globalThis.VaultView = VaultView;
