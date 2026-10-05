import { type ReactNode, useEffect, useState } from 'react';
import { ArrowDownToLine, ArrowUpRight, Check, Clipboard, FileCheck2, FileUp, Fingerprint, History, KeyRound, LogOut, ShieldAlert, ShieldCheck, Trash2, UserRound, Users, X } from 'lucide-react';
import './account.css';

type User = { id: string; secure_net_id: string; full_name: string; username: string; email: string; public_key: string; public_key_fingerprint: string; created_at: number };
type Stats = { files_stored: number; storage_bytes: number; files_sent: number; files_received: number; successful_transfers: number; rejected_transfers: number; tampering_events: number };
export type AccountState = { user: User; stats: Stats; csrf: string };
type FileRecord = { id: string; original_filename: string; size: number; mime_type: string; sha256: string; encryption_algorithm?: string; created_at: number; transfer_id?: string; sender_secure_id?: string; sender_username?: string; transfer_status?: string };
type Transfer = { id: string; sender_secure_id: string; receiver_secure_id: string; original_filename: string; size: number; algorithm: string; key_exchange: string; status: string; source_sha256?: string; receiver_sha256?: string; total_chunks: number; verified_chunks: number; matched_bytes: number; duration_ms?: number; transfer_speed?: number; created_at: number; receipt?: Record<string, unknown> };
type Event = { id: string; transfer_id?: string; event_type: string; severity: string; metadata: Record<string, unknown>; created_at: number };
type Props = { account: AccountState | null; onAccount: (value: AccountState | null) => void };
type View = 'dashboard' | 'files' | 'send' | 'received' | 'history' | 'events' | 'profile';

const size = (value: number) => value >= 1073741824 ? `${(value / 1073741824).toFixed(1)} GB` : value >= 1048576 ? `${(value / 1048576).toFixed(1)} MB` : value >= 1024 ? `${(value / 1024).toFixed(1)} KB` : `${value} B`;
const date = (value: number) => new Date(value * 1000).toLocaleString();

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

export function AccountPanel({ account, onAccount }: Props) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [view, setView] = useState<View>('dashboard');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({ full_name: '', username: '', email: '', password: '', confirm_password: '', login: '' });
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [received, setReceived] = useState<FileRecord[]>([]);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [receiverId, setReceiverId] = useState('');
  const [receiver, setReceiver] = useState<{ secure_net_id: string; username: string; public_key_fingerprint: string } | null>(null);
  const [algorithm, setAlgorithm] = useState('AES-256-GCM');
  const [receipt, setReceipt] = useState<Record<string, unknown> | null>(null);

  async function request<T>(url: string, options: RequestInit = {}) {
    const headers = new Headers(options.headers);
    if (account?.csrf) headers.set('X-Account-CSRF', account.csrf);
    const response = await fetch(`${API_BASE_URL}${url}`, { ...options, headers, credentials: 'include' });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) onAccount(null);
      throw new Error(typeof data.detail === 'string' ? data.detail : 'The account operation failed.');
    }
    const csrf = response.headers.get('X-Account-CSRF');
    if (csrf && account) onAccount({ ...account, csrf });
    return data as T;
  }

  async function run(action: () => Promise<void>) {
    setLoading(true); setError(''); setNotice('');
    try { await action(); } catch (exception) { setError(exception instanceof Error ? exception.message : 'The account operation failed.'); }
    finally { setLoading(false); }
  }

  useEffect(() => {
    if (account) return;
    fetch(`${API_BASE_URL}/api/account/me`, { credentials: 'include' }).then(async response => {
      if (!response.ok) return null;
      const data = await response.json();
      return { ...data, csrf: response.headers.get('X-Account-CSRF') || '' };
    }).then(data => {
      if (data) onAccount(data);
    }).catch(() => {});
  }, [account, onAccount]);

  useEffect(() => {
    if (!account) return;
    void refresh(view);
  }, [account?.user.id, view]);

  async function refresh(current: View) {
    if (!account) return;
    await run(async () => {
      if (current === 'files' || current === 'dashboard') {
        const data = await request<{ files: FileRecord[] }>('/api/account/files'); setFiles(data.files);
      }
      if (current === 'received') setReceived((await request<{ files: FileRecord[] }>('/api/account/received')).files);
      if (current === 'history') setTransfers((await request<{ transfers: Transfer[] }>('/api/account/transfers')).transfers);
      if (current === 'events') setEvents((await request<{ events: Event[] }>('/api/account/events')).events);
      if (current === 'dashboard') {
        const data = await request<{ user: User; stats: Stats }>('/api/account/me'); onAccount({ ...account, ...data });
      }
    });
  }

  async function auth() {
    await run(async () => {
      const endpoint = mode === 'login' ? '/api/account/login' : '/api/account/register';
      const payload = mode === 'login' ? { login: form.login || form.email, password: form.password } : form;
      const response = await fetch(`${API_BASE_URL}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), credentials: 'include' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Authentication failed.');
      onAccount({ ...data, csrf: response.headers.get('X-Account-CSRF') || '' }); setView('dashboard'); setForm({ full_name: '', username: '', email: '', password: '', confirm_password: '', login: '' });
    });
  }

  async function logout() {
    await run(async () => { await request('/api/account/logout', { method: 'POST' }); onAccount(null); });
  }

  async function upload() {
    if (!file) return;
    await run(async () => {
      const body = new FormData(); body.append('file', file);
      await request('/api/account/files', { method: 'POST', body }); setFile(null); setNotice('File encrypted and saved in your private storage.'); await refresh('files');
    });
  }

  async function verifyReceiver() {
    await run(async () => { const data = await request<{ secure_net_id: string; username: string; public_key_fingerprint: string }>(`/api/account/users/${encodeURIComponent(receiverId)}`); setReceiver(data); });
  }

  async function send() {
    if (!file || !receiver) return;
    await run(async () => {
      const body = new FormData(); body.append('receiver_id', receiver.secure_net_id); body.append('algorithm', algorithm); body.append('file', file);
      const data = await request<{ receipt: Record<string, unknown> }>('/api/account/transfers', { method: 'POST', body }); setReceipt(data.receipt); setFile(null); setNotice('The transfer was encrypted, checked, and delivered.'); await refresh('dashboard');
    });
  }

  if (!account) return <AuthView mode={mode} setMode={setMode} form={form} setForm={value => setForm(value as typeof form)} loading={loading} error={error} run={auth} />;

  const nav: [View, string, ReactNode][] = [['dashboard', 'Dashboard', <UserRound size={15} key="dashboard" />], ['files', 'My Files', <FileUp size={15} key="files" />], ['send', 'Send Data', <ArrowUpRight size={15} key="send" />], ['received', 'Received Data', <FileCheck2 size={15} key="received" />], ['history', 'Transfer History', <History size={15} key="history" />], ['events', 'Security Events', <ShieldAlert size={15} key="events" />], ['profile', 'Profile', <Fingerprint size={15} key="profile" />]];
  return <section className="account-shell">
    <aside className="account-sidebar"><div className="account-user"><span className="avatar">{account.user.username[0].toUpperCase()}</span><div><strong>@{account.user.username}</strong><span className="mono">{account.user.secure_net_id}</span></div></div><nav aria-label="SecureNet account">{nav.map(([key, label, icon]) => <button className={view === key ? 'account-nav active' : 'account-nav'} key={key} onClick={() => { setView(key); setError(''); }}>{icon}{label}</button>)}</nav><button className="account-nav logout" disabled={loading} onClick={logout}><LogOut size={15} />Logout</button></aside>
    <div className="account-content"><div className="account-toolbar"><div><span className="eyebrow">SECURENET ACCOUNT</span><h3>{view === 'dashboard' ? `Welcome, @${account.user.username}` : nav.find(item => item[0] === view)?.[1]}</h3></div><div className="secure-id"><span className="mono">YOUR SECURENET ID</span><strong>{account.user.secure_net_id}</strong><button className="icon-button" title="Copy SecureNet ID" aria-label="Copy SecureNet ID" onClick={() => { void navigator.clipboard.writeText(account.user.secure_net_id); setNotice('SecureNet ID copied.'); }}><Clipboard size={15} /></button></div></div>{error && <div className="account-error" role="alert"><X size={15} />{error}</div>}{notice && <div className="account-notice" role="status"><Check size={15} />{notice}</div>}
      {view === 'dashboard' && <Dashboard account={account} files={files} setView={setView} />}
      {view === 'files' && <FileView files={files} file={file} setFile={setFile} upload={upload} loading={loading} request={request} refresh={() => refresh('files')} />}
      {view === 'send' && <SendView receiverId={receiverId} setReceiverId={setReceiverId} receiver={receiver} verify={verifyReceiver} file={file} setFile={setFile} algorithm={algorithm} setAlgorithm={setAlgorithm} send={send} loading={loading} receipt={receipt} />}
      {view === 'received' && <ReceivedView files={received} />}
      {view === 'history' && <HistoryView transfers={transfers} request={request} />}
      {view === 'events' && <EventView events={events} />}
      {view === 'profile' && <ProfileView account={account} />}
    </div>
  </section>;
}

function AuthView({ mode, setMode, form, setForm, loading, error, run }: { mode: 'login' | 'register'; setMode: (value: 'login' | 'register') => void; form: Record<string, string>; setForm: (value: Record<string, string>) => void; loading: boolean; error: string; run: () => Promise<void> }) {
  const update = (key: string, value: string) => setForm({ ...form, [key]: value });
  return <section className="auth-card"><div className="auth-copy"><span className="eyebrow">{mode === 'login' ? 'WELCOME BACK' : 'CREATE YOUR IDENTITY'}</span><h3>{mode === 'login' ? 'Log in to SecureNet.' : 'Get your SecureNet ID.'}</h3><p>{mode === 'login' ? 'Your private files, transfers, receipts, and security events live behind your account.' : 'Your account gets a human-friendly SecureNet ID and a protected Ed25519 identity.'}</p><div className="auth-switch"><button className={mode === 'login' ? 'active' : ''} onClick={() => setMode('login')}>LOGIN</button><button className={mode === 'register' ? 'active' : ''} onClick={() => setMode('register')}>REGISTER</button></div></div><form onSubmit={event => { event.preventDefault(); void run(); }} className="auth-form">{mode === 'register' && <><label>Full name<input required value={form.full_name} onChange={event => update('full_name', event.target.value)} /></label><label>Username<input required pattern="[A-Za-z0-9_]{3,32}" value={form.username} onChange={event => update('username', event.target.value)} /></label><label>Email<input required type="email" value={form.email} onChange={event => update('email', event.target.value)} /></label></>}{mode === 'login' && <label>Username or email<input required value={form.login} onChange={event => update('login', event.target.value)} /></label>}<label>Password<input required type="password" value={form.password} onChange={event => update('password', event.target.value)} /></label>{mode === 'register' && <label>Confirm password<input required type="password" value={form.confirm_password} onChange={event => update('confirm_password', event.target.value)} /></label>}<button className="button black" disabled={loading}>{loading ? 'WORKING…' : mode === 'login' ? 'LOGIN' : 'CREATE ACCOUNT'}<ArrowUpRight size={16} /></button>{error && <p className="auth-error" role="alert">{error}</p>}<p className="microcopy">Passwords are stored as Argon2id hashes. Private identity keys are protected with the account master secret and never shown here.</p></form></section>;
}

function Dashboard({ account, files, setView }: { account: AccountState; files: FileRecord[]; setView: (view: View) => void }) {
  const percent = Math.min(100, account.stats.storage_bytes / 1073741824 / 10 * 100);
  return <div className="account-view"><div className="account-hero"><div><span className="eyebrow">YOUR PRIVATE CONTROL ROOM</span><h3>Who are you sending to?</h3><p>Use a SecureNet ID, verify the receiver’s public identity, then send through an authenticated encrypted session.</p></div><div className="account-key-card"><KeyRound size={22} /><span className="mono">PUBLIC KEY FINGERPRINT</span><code>{account.user.public_key_fingerprint}</code><span className="mono">PRIVATE KEY / PROTECTED</span></div></div><div className="stats-grid"><Stat label="MY FILES" value={account.stats.files_stored} onClick={() => setView('files')} /><Stat label="SENT" value={account.stats.files_sent} onClick={() => setView('history')} /><Stat label="RECEIVED" value={account.stats.files_received} onClick={() => setView('received')} /><Stat label="VERIFIED" value={account.stats.successful_transfers} onClick={() => setView('history')} /><Stat label="REJECTED" value={account.stats.rejected_transfers} onClick={() => setView('events')} /><Stat label="TAMPERING EVENTS" value={account.stats.tampering_events} onClick={() => setView('events')} /></div><div className="storage-card"><div><span className="mono">PRIVATE STORAGE</span><strong>{size(account.stats.storage_bytes)} / 10 GB</strong></div><progress value={percent} max={100} aria-label="Storage used" /></div><div className="quick-actions"><button className="button black" onClick={() => setView('send')}><ArrowUpRight size={16} />SEND SECURE DATA</button><button className="button" onClick={() => setView('files')}><FileUp size={16} />OPEN MY FILES</button></div><p className="microcopy">{files.length ? `${files.length} private file${files.length === 1 ? '' : 's'} ready.` : 'Upload your first private file to begin.'} Server-side ownership checks protect every account resource.</p></div>;
}

function Stat({ label, value, onClick }: { label: string; value: number; onClick: () => void }) { return <button className="account-stat" onClick={onClick}><span className="mono">{label}</span><strong>{value}</strong><ArrowUpRight size={14} /></button>; }

function FileView({ files, file, setFile, upload, loading, request, refresh }: { files: FileRecord[]; file: File | null; setFile: (file: File | null) => void; upload: () => Promise<void>; loading: boolean; request: <T>(url: string, options?: RequestInit) => Promise<T>; refresh: () => Promise<void> }) {
  return <div className="account-view"><div className="account-section-intro"><div><span className="eyebrow">PRIVATE STORAGE</span><h3>My files.</h3><p>Files are encrypted at rest with a per-file AES-256-GCM key. Only your account can request a download.</p></div><label className="account-upload"><FileUp size={23} /><strong>{file ? file.name : 'Choose a file to upload'}</strong><span className="mono">100 MB MAX / ENCRYPTED STORAGE</span><input type="file" className="sr-only" onChange={event => setFile(event.target.files?.[0] || null)} /></label>{file && <button className="button black" disabled={loading} onClick={() => void upload()}>STORE PRIVATELY <ArrowUpRight size={15} /></button>}</div>{files.length ? <div className="data-table">{files.map(item => <div className="data-row" key={item.id}><div><strong>{item.original_filename}</strong><span className="mono">{size(item.size)} / {item.mime_type}</span></div><code>{item.sha256.slice(0, 18)}…</code><div className="row-actions"><button title="Integrity" aria-label={`Check integrity of ${item.original_filename}`} onClick={() => void request<{ verified: boolean }>(`/api/account/files/${item.id}/integrity`).then(result => window.alert(result.verified ? 'SHA-256: VERIFIED' : 'SHA-256: MISMATCH')).catch(() => {})}><FileCheck2 size={15} /></button><button title="Tamper simulation" aria-label={`Simulate tampering of ${item.original_filename}`} onClick={() => void request<{ message: string }>(`/api/account/attacks/file`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ file_id: item.id, mode: 'file_tamper' }) }).then(result => window.alert(result.message)).catch(() => {})}><ShieldAlert size={15} /></button><a title="Download" aria-label={`Download ${item.original_filename}`} href={`${API_BASE_URL}/api/account/files/${item.id}/download`} download><ArrowDownToLine size={15} /></a><button title="Delete" aria-label={`Delete ${item.original_filename}`} onClick={() => void request(`/api/account/files/${item.id}`, { method: 'DELETE' }).then(refresh).catch(() => {})}><Trash2 size={15} /></button></div></div>)}</div> : <div className="account-empty"><FileUp size={28} /><p>No private files yet.</p></div>}<p className="microcopy">SHA-256 is used as the file fingerprint. Encryption keeps the file secret; the fingerprint helps verify that it was not changed. The tamper button modifies only a disposable copy.</p></div>;
}

function SendView({ receiverId, setReceiverId, receiver, verify, file, setFile, algorithm, setAlgorithm, send, loading, receipt }: { receiverId: string; setReceiverId: (value: string) => void; receiver: { secure_net_id: string; username: string; public_key_fingerprint: string } | null; verify: () => Promise<void>; file: File | null; setFile: (file: File | null) => void; algorithm: string; setAlgorithm: (value: string) => void; send: () => Promise<void>; loading: boolean; receipt: Record<string, unknown> | null }) {
  return <div className="account-view"><div className="account-section-intro"><span className="eyebrow">PRIVATE USER-TO-USER TRANSFER</span><h3>Send secure data.</h3><p>Enter the receiver’s SecureNet ID. The backend verifies the account and public identity before a fresh X25519 session starts.</p></div><div className="send-card"><label>Receiver SecureNet ID<div className="inline-form"><input placeholder="SN-7K4P-92XM" value={receiverId} onChange={event => { setReceiverId(event.target.value.toUpperCase()); }} /><button className="button" disabled={loading || receiverId.length < 11} onClick={() => void verify()}>VERIFY RECEIVER <ShieldCheck size={15} /></button></div></label>{receiver && <div className="receiver-verified"><Check size={20} /><div><strong>RECEIVER VERIFIED / @{receiver.username}</strong><span className="mono">{receiver.secure_net_id} / ED25519 FINGERPRINT {receiver.public_key_fingerprint}</span></div></div>}<label className="account-upload send-file"><FileUp size={22} /><strong>{file ? file.name : 'Choose the file to send'}</strong><span className="mono">CHUNKED + ENCRYPTED + HASHED</span><input type="file" className="sr-only" onChange={event => setFile(event.target.files?.[0] || null)} /></label><div className="algorithm-choice"><span className="mono">LOCK DATA WITH</span><select value={algorithm} onChange={event => setAlgorithm(event.target.value)}><option>AES-256-GCM</option><option>ChaCha20-Poly1305</option></select><button className="button primary" disabled={!receiver || !file || loading} onClick={() => void send()}>SEND SECURELY <ArrowUpRight size={16} /></button></div></div>{receipt && <Receipt receipt={receipt} />}</div>;
}

function Receipt({ receipt }: { receipt: Record<string, unknown> }) { return <div className="receipt-card"><div className="receipt-heading"><ShieldCheck size={25} /><div><span className="eyebrow">SECURE TRANSFER RECEIPT</span><h3>{String(receipt.status || 'COMPLETE')}</h3></div></div><dl><dt>TRANSFER ID</dt><dd>{String(receipt.transfer_id)}</dd><dt>SENDER</dt><dd>{String(receipt.sender_id)}</dd><dt>RECEIVER</dt><dd>{String(receipt.receiver_id)}</dd><dt>FILE</dt><dd>{String(receipt.file)}</dd><dt>ENCRYPTION</dt><dd>{String(receipt.algorithm)}</dd><dt>KEY EXCHANGE</dt><dd>{String(receipt.key_exchange)} / {String(receipt.key_derivation)}</dd><dt>SOURCE SHA-256</dt><dd>{String(receipt.source_sha256)}</dd><dt>RECEIVER SHA-256</dt><dd>{String(receipt.receiver_sha256)}</dd><dt>CHUNKS</dt><dd>{String(receipt.verified_chunks)} / {String(receipt.total_chunks)} verified</dd><dt>BYTES</dt><dd>{String(receipt.matched_bytes)} / {String(receipt.total_compared_bytes)} match</dd></dl><ChunkIntegrity receipt={receipt} /><strong className="receipt-status">✓ BYTE-FOR-BYTE VERIFIED</strong></div>; }

function ChunkIntegrity({ receipt }: { receipt: Record<string, unknown> }) {
  const total = Math.max(0, Number(receipt.total_chunks) || 0);
  const verified = Math.max(0, Math.min(total, Number(receipt.verified_chunks) || 0));
  const visible = Math.min(total, 256);
  return <div className="chunk-verification" aria-label="Chunk integrity results"><div className="chunk-verification-heading"><span className="mono">CHUNK INTEGRITY</span><strong>{verified} / {total} MATCH</strong></div><div className="chunk-status-grid" role="list">{Array.from({ length: visible }, (_, index) => { const matched = index < verified; return <span key={index} role="listitem" className={matched ? 'chunk-state matched' : 'chunk-state rejected'} title={`Chunk ${String(index + 1).padStart(2, '0')}: ${matched ? 'MATCH' : 'UNVERIFIED'}`} aria-label={`Chunk ${index + 1}: ${matched ? 'MATCH' : 'UNVERIFIED'}`}>{matched ? '✓' : '!'}</span>; })}</div>{total > visible && <span className="mono microcopy">SHOWING FIRST {visible} OF {total} CHUNKS</span>}</div>;
}

function ReceivedView({ files }: { files: FileRecord[] }) { return <div className="account-view"><div className="account-section-intro"><span className="eyebrow">ONLY FOR YOU</span><h3>Received data.</h3><p>Files appear here only after the sender’s encrypted transfer passed chunk checks, SHA-256, and byte comparison.</p></div>{files.length ? <div className="data-table">{files.map(item => <div className="data-row" key={item.id}><div><strong>{item.original_filename}</strong><span className="mono">FROM {item.sender_secure_id} / @{item.sender_username}</span></div><code>{item.sha256.slice(0, 18)}…</code><a className="button small" href={`${API_BASE_URL}/api/account/files/${item.id}/download`} download>DOWNLOAD <ArrowDownToLine size={14} /></a></div>)}</div> : <div className="account-empty"><Users size={28} /><p>No received files yet.</p></div>}</div>; }
function HistoryView({ transfers, request }: { transfers: Transfer[]; request: <T>(url: string, options?: RequestInit) => Promise<T> }) { return <div className="account-view"><div className="account-section-intro"><span className="eyebrow">AUDITABLE RECORDS</span><h3>Transfer history.</h3><p>Every receipt records the endpoints, algorithm, key exchange, hashes, verified chunks, timing, and final status—never secret keys.</p></div>{transfers.length ? <div className="data-table">{transfers.map(item => <div className="data-row history-row" key={item.id}><div><strong>{item.original_filename}</strong><span className="mono">{item.sender_secure_id} → {item.receiver_secure_id}</span></div><span className={`status-text ${item.status}`}>{item.status === 'verified' ? '✓ VERIFIED' : item.status.toUpperCase()}</span><span className="mono">{item.algorithm} / {item.total_chunks} CHUNKS</span><button className="text-button" onClick={() => void request<Transfer>(`/api/account/transfers/${item.id}/receipt`).then(result => window.alert(JSON.stringify(result.receipt || result, null, 2))).catch(() => {})}>RECEIPT</button></div>)}</div> : <div className="account-empty"><History size={28} /><p>No transfers yet.</p></div>}</div>; }
function EventView({ events }: { events: Event[] }) { return <div className="account-view"><div className="account-section-intro"><span className="eyebrow">SAFE AUDIT TRAIL</span><h3>Security events.</h3><p>Events identify operations and outcomes. Passwords, private keys, raw keys, and unnecessary plaintext are excluded.</p></div>{events.length ? <div className="event-list">{events.map(event => <div className="account-event" key={event.id}><span className={`event-severity ${event.severity}`} /><div><strong>{event.event_type}</strong><span className="mono">{date(event.created_at)}{event.transfer_id ? ` / ${event.transfer_id}` : ''}</span></div><code>{JSON.stringify(event.metadata)}</code></div>)}</div> : <div className="account-empty"><ShieldAlert size={28} /><p>No security events yet.</p></div>}</div>; }
function ProfileView({ account }: { account: AccountState }) { return <div className="account-view"><div className="profile-card"><div className="profile-avatar">{account.user.username[0].toUpperCase()}</div><div><span className="eyebrow">MY PROFILE</span><h3>{account.user.full_name}</h3><p>@{account.user.username} / {account.user.email}</p></div></div><dl className="profile-list"><dt>SECURENET ID</dt><dd>{account.user.secure_net_id}</dd><dt>PUBLIC KEY FINGERPRINT</dt><dd>{account.user.public_key_fingerprint}</dd><dt>PUBLIC KEY</dt><dd className="profile-key">{account.user.public_key}</dd><dt>ACCOUNT CREATED</dt><dd>{date(account.user.created_at)}</dd><dt>PRIVATE KEY</dt><dd><span className="protected-value"><KeyRound size={14} /> PROTECTED / NEVER DISPLAYED</span></dd><dt>PASSWORD</dt><dd><span className="protected-value"><ShieldCheck size={14} /> ARGON2ID HASH / NEVER DISPLAYED</span></dd></dl></div>; }
