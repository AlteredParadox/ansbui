// Login screen shown when built-in auth is enabled and the current
// session is absent or expired. Rendered by Boot in place of the
// picker/app; on success it calls onSuccess to re-run the boot flow.
const { useState: useStateLogin } = React;

function LoginView({ onSuccess }) {
  const [password, setPassword] = useStateLogin('');
  const [busy, setBusy] = useStateLogin(false);
  const [error, setError] = useStateLogin('');

  const submit = async (e) => {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError('');
    try {
      await window.AnsbuiAPI.login(password);
      setPassword('');
      onSuccess();
    } catch (err) {
      // 429 (throttled) and 401 (wrong password) both surface here.
      setError(err.message || 'Login failed');
      setBusy(false);
    }
  };

  return (
    <div className="boot-screen">
      <form className="boot-card" onSubmit={submit}>
        <div className="boot-brand">
          <BrandMark/>
          <div>
            <h1 className="boot-title">ansbui</h1>
            <div className="boot-sub mono">sign in to continue</div>
          </div>
        </div>
        {error && <div className="boot-error">{error}</div>}
        <label htmlFor="login-pw" className="cm-field-label" style={{ marginTop: 4 }}>Password</label>
        <input
          id="login-pw"
          className="input mono"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={e => setPassword(e.target.value)}
          disabled={busy}
          style={{ marginTop: 6 }}
        />
        <button type="submit" className="btn primary" disabled={busy || !password} style={{ marginTop: 14, width: '100%', justifyContent: 'center' }}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}

window.LoginView = LoginView;
