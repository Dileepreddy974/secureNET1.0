import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ArrowDown, ArrowDownToLine, ArrowRight, ArrowUpRight, Check, ChevronLeft, ChevronRight, CircleHelp, Copy, FileUp, Fingerprint, KeyRound, LockKeyhole, MoveUpRight, Pause, Play, Radio, RefreshCw, ShieldCheck, Terminal, Unplug, X } from 'lucide-react';
import '@fontsource/space-grotesk/400.css';
import '@fontsource/space-grotesk/500.css';
import '@fontsource/space-grotesk/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import './styles.css';
import './evidence.css';
import { HashLab, type HashComparison } from './HashLab';
import { AccountPanel, type AccountState } from './AccountPanel';
import { EducationLab } from './EducationLab';
import './education.css';

type Tab = 'messages' | 'hashing' | 'files' | 'attacks' | 'benchmarks' | 'education' | 'guide' | 'account';
type WireRecord = { sequence: number; nonce: string; header: string; ciphertext: string; tag: string; wire_bytes: number; ciphertext_bytes: number; truncated: boolean };
type Handshake = { algorithm: string; duration_ms: number; sender_fingerprint: string; receiver_fingerprint: string; sender_public: string; receiver_public: string };
type Session = { csrf: string; handshake: Handshake; max_upload: number };
type Message = { text: string; plaintext_hex: string; record: WireRecord; encryption_ms: number; round_trip_ms: number; message_bytes: number; payload_bytes: number; sha256: string };
type Transfer = { id: string; download_id: string; name: string; size: number; chunks: number; source_sha256: string; receiver_sha256: string; duration_ms: number; throughput_mbps: number; verified: boolean; record: WireRecord | null };
type AttackResult = { mode: string; code: string; rejected: boolean; original?: WireRecord; transmitted?: WireRecord };
type BenchRow = { algorithm: string; size: number; encrypt_ms: number; decrypt_ms: number; p95_encrypt_ms: number; throughput_mbps: number; iterations: number };
type Benchmark = { rows: BenchRow[]; python: string; platform: string; machine: string; cryptography: string; scope: string; timestamp: number; warmup: number };
type LabEvent = { stage: string; detail: Record<string, string | number | boolean>; timestamp: number };
const algorithms = ['AES-256-GCM', 'ChaCha20-Poly1305'];
const stages = ['Text to bytes', 'Lock', 'Send', 'Check', 'Unlock'];
const stageNotes = [
  'The computer turns your letters into numbers called bytes, using UTF-8. It adds a small label so the receiver knows this is a message.',
  'A secret key locks your message. The locked data is called ciphertext. A one-time number (nonce) and a tamper-check value (tag) help protect it.',
  'The locked message travels from the sender to the receiver over TCP, the network connection. Someone watching that connection sees locked data.',
  'The receiver checks the message number and tamper-check value. Changed or repeated messages are rejected.',
  'The right key unlocks the message. Your readable text is shown only after the checks pass. This is called decryption.',
];
const bytes = (n: number) => n >= 1048576 ? `${(n / 1048576).toFixed(1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`;
const hexBytes = (value: string) => value.match(/.{1,2}/g) || [];

function App() {
  const [tab, setTab] = useState<Tab>('messages');
  const [session, setSession] = useState<Session | null>(null);
  const [algorithm, setAlgorithm] = useState(algorithms[0]);
  const [text, setText] = useState('Meet me on the other side.');
  const [result, setResult] = useState<Message | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [events, setEvents] = useState<LabEvent[]>([]);
  const [step, setStep] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const [replay, setReplay] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [file, setFile] = useState<File | null>(null);
  const [transfer, setTransfer] = useState<Transfer | null>(null);
  const [progress, setProgress] = useState({ chunk: 0, sent: 0, total: 0 });
  const [attackResult, setAttackResult] = useState<AttackResult | null>(null);
  const [benchmark, setBenchmark] = useState<Benchmark | null>(null);
  const [copied, setCopied] = useState(false);
  const [streamLive, setStreamLive] = useState(false);
  const [account, setAccount] = useState<AccountState | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const liveMessage = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${API_BASE_URL}/api/session`, { signal: controller.signal, credentials: 'include' }).then(r => r.ok ? r.json() : null).then(value => {
      if (value) { setSession(value); setAlgorithm(value.handshake.algorithm); }
    }).catch(() => {});
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!session) { setStreamLive(false); return; }
    const source = new EventSource(`${API_BASE_URL}/api/events`, { withCredentials: true });
    source.onopen = () => setStreamLive(true);
    source.onerror = () => setStreamLive(false);
    source.onmessage = event => {
      const value = JSON.parse(event.data) as LabEvent;
      setEvents(current => [...current.slice(-29), value]);
      if (liveMessage.current) {
        const liveStages: Record<string, number> = { encode: 0, encrypt: 1, transmit: 2, verify: 4 };
        if (value.stage in liveStages) setStep(liveStages[value.stage]);
      }
      if (value.stage === 'file_chunk') setProgress(value.detail as { chunk: number; sent: number; total: number });
      if (value.stage === 'closed') { setSession(null); source.close(); }
    };
    return () => { source.close(); setStreamLive(false); };
  }, [session]);

  useEffect(() => {
    if (!playing) return;
    if (step >= 4) { setPlaying(false); return; }
    const timer = window.setTimeout(() => setStep(current => current + 1), 1400 / speed);
    return () => window.clearTimeout(timer);
  }, [playing, step, speed]);

  const API_BASE_URL = import.meta.env.VITE_API_URL || '';

  async function api<T>(url: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers);
    if (session) headers.set('X-CSRF-Token', session.csrf);
    const response = await fetch(`${API_BASE_URL}${url}`, { ...options, headers, credentials: 'include' });
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 401) setSession(null);
      throw new Error(typeof data.detail === 'string' ? data.detail : 'Check your input and try again.');
    }
    return data;
  }

  async function perform(name: string, action: () => Promise<void>) {
    setBusy(name); setError('');
    try { await action(); } catch (e) { setError(e instanceof Error ? e.message : 'Connection failed. Please retry.'); }
    finally { setBusy(''); }
  }

  const jsonOptions = (body: unknown) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

  async function start() {
    await perform('connect', async () => {
      const next = await api<Session>('/api/session', jsonOptions({ algorithm }));
      setSession(next); setEvents([]); setResult(null); setTransfer(null); setAttackResult(null);
      setStep(-1); setPlaying(false); setReplay(false); setProgress({ chunk: 0, sent: 0, total: 0 });
    });
  }

  async function send() {
    liveMessage.current = true;
    setPlaying(false); setReplay(false); setResult(null); setStep(0);
    await perform('message', async () => {
      const next = await api<Message>('/api/messages', jsonOptions({ text }));
      setResult(next); setStep(4);
    });
    liveMessage.current = false;
  }

  async function upload() {
    if (!file) return;
    setTransfer(null); setProgress({ chunk: 0, sent: 0, total: file.size });
    await perform('file', async () => {
      const next = await api<Transfer>(`/api/files?name=${encodeURIComponent(file.name)}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: file,
      });
      setTransfer(next); setProgress({ chunk: next.chunks, sent: next.size, total: next.size });
    });
  }

  function chooseFile(chosen?: File) {
    if (!chosen) return;
    if (chosen.size > (session?.max_upload || 10 * 1024 * 1024)) { setError('Public demo limit: 10 MiB per file.'); return; }
    setError(''); setFile(chosen); setTransfer(null); setProgress({ chunk: 0, sent: 0, total: chosen.size });
  }

  function downloadCSV() {
    if (!benchmark) return;
    const lines = ['algorithm,size_bytes,encrypt_median_ms,decrypt_median_ms,encrypt_p95_ms,throughput_MiB_s,iterations',
      ...benchmark.rows.map(r => [r.algorithm, r.size, r.encrypt_ms, r.decrypt_ms, r.p95_encrypt_ms, r.throughput_mbps, r.iterations].join(','))];
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }));
    const a = document.createElement('a'); a.href = url; a.download = 'securenet-benchmark.csv'; a.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const connected = Boolean(session);
  const lastEvent = events.at(-1);
  const activeAlgorithm = session?.handshake.algorithm || algorithm;
  const disabled = !connected || Boolean(busy);

  return <>
    <a href="#workspace" className="skip-link">Skip to laboratory</a>
    <header className="site-header">
      <a className="brand" href="#" onClick={() => setTab('messages')} aria-label="SecureNet home"><span className="brand-mark">s<span>n</span></span><span>SECURENET<span className="brand-lab"> / LAB</span></span></a>
      <nav aria-label="Laboratory pages">{(['messages', 'hashing', 'files', 'attacks', 'benchmarks', 'education', 'guide', 'account'] as Tab[]).map((name, i) => <button key={name} className={tab === name ? 'nav-button active' : 'nav-button'} aria-current={tab === name ? 'page' : undefined} onClick={() => { setTab(name); setError(''); }}><span className="nav-index">0{i + 1}</span>{name}</button>)}</nav>
      <span className="header-edition mono">NETWORKS<br />EXPERIMENT NO. 01</span>
    </header>

    <main>
      <section className="hero" aria-labelledby="hero-title">
        <div className="hero-copy"><div className="eyebrow"><span className="tiny-square" /> NETWORK SECURITY, MADE SIMPLE</div><h1 id="hero-title">PRIVATE DATA.<br /><span>PUBLIC PROOF.</span><span className="title-period">↗</span></h1><p>Lock a message. Make a fingerprint.<br />Explore encryption, MD5, and SHA-256 — one simple step at a time.</p></div>
        <div className="hero-stamp" aria-hidden="true"><div className="stamp-corners"><span>256</span><LockKeyhole size={26} strokeWidth={1.6} /></div><div className="asterisk">✳</div><div className="stamp-bottom mono">TRUST THE MATH.<br />VERIFY THE MESSAGE.</div></div>
      </section>

      <div className="principles mono"><span><ShieldCheck size={15} /> LOCK + UNLOCK MESSAGES</span><span><Fingerprint size={15} /> MD5 + SHA-256 FINGERPRINTS</span><span><Radio size={15} /> REAL NETWORK CONNECTIONS</span><span className="principles-last">BUILT TO BE UNDERSTOOD <ArrowDown size={15} /></span></div>

      <section className="workspace" id="workspace">
        <div className="section-heading"><div><span className="eyebrow">01 / THE WORKBENCH</span><h2>{{ messages: 'Lock it. Send it. Unlock it.', hashing: 'Make a digital fingerprint.', files: 'Every byte. Protected.', attacks: 'Try to change the message.', benchmarks: 'Compare the speed.', education: 'Learn the older ideas.', guide: 'The simple explanation.', account: account ? `Welcome, @${account.user.username}` : 'Your secure account.' }[tab]}</h2></div><span className={`status-pill ${connected ? 'connected' : ''}`}><span className="status-dot" />{tab === 'account' ? account ? 'ACCOUNT SIGNED IN' : 'ACCOUNT OFFLINE' : connected ? 'CONNECTED + VERIFIED' : 'NOT CONNECTED'}</span></div>

        {tab !== 'account' && <div className="connection-bar"><div className="connection-label"><Terminal size={18} /><span className="mono">{tab === 'hashing' ? 'HASHING LAB' : 'NETWORK CONNECTION'}</span><span className="muted desktop-only">{tab === 'hashing' ? 'MD5 + SHA-256' : 'Sender → Receiver'}</span></div><div className="connection-actions">{tab !== 'hashing' && <><label className="sr-only" htmlFor="algorithm">Encryption algorithm</label><select id="algorithm" value={algorithm} disabled={Boolean(busy)} onChange={e => setAlgorithm(e.target.value)}>{algorithms.map(a => <option key={a}>{a}</option>)}</select></>}<button className="button primary small" disabled={Boolean(busy)} onClick={start}>{busy === 'connect' ? 'CONNECTING…' : connected ? 'NEW SESSION' : 'CONNECT'}<ArrowUpRight size={16} /></button>{connected && <button className="icon-button" aria-label="Disconnect session" title="Disconnect session" disabled={Boolean(busy)} onClick={() => perform('disconnect', async () => { await api('/api/session', { method: 'DELETE' }); setSession(null); })}><Unplug size={17} /></button>}</div></div>}
        {connected && algorithm !== activeAlgorithm && tab !== 'hashing' && <p className="inline-note">Select NEW SESSION to switch to {algorithm} with a new secret key.</p>}
        {tab === 'messages' && <div className="beginner-note"><p><strong>Encryption locks data. Hashing makes a fingerprint.</strong> Start with MD5 and SHA-256 to see how fingerprints work.</p><button className="text-button" onClick={() => setTab('hashing')}>TRY MD5 + SHA-256 <ArrowUpRight size={14} /></button></div>}
        {error && <div className="error-banner" role="alert"><span><strong>OPERATION STOPPED / </strong>{error}</span><button className="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><X size={18} /></button></div>}

        {tab === 'hashing' && <HashLab connected={connected} busy={Boolean(busy)} run={action => perform('hash', action)} compare={(original, changed) => api<HashComparison>('/api/hashes', jsonOptions({ original, changed }))} />}
        {tab === 'education' && <EducationLab busy={Boolean(busy)} run={action => perform('education', action)} />}
        {tab === 'account' && <AccountPanel account={account} onAccount={setAccount} />}

        {tab === 'messages' && <>
          <div className="transfer-grid">
            <article className="endpoint sender"><div className="panel-top"><span className="mono">A / SENDER</span><span className="mini-tag">ORIGINAL TEXT</span></div><label htmlFor="message" className="field-label">Your readable message</label><textarea id="message" value={text} maxLength={16000} disabled={Boolean(busy)} onChange={e => setText(e.target.value)} spellCheck={false} /><div className="input-meta mono"><span>{new TextEncoder().encode(text).length} BYTES / UTF-8</span><span>16 KiB MAX</span></div><button className="button black send-button" disabled={disabled || !text || new TextEncoder().encode(text).length > 16384} onClick={send}>{busy === 'message' ? 'TRANSFERRING…' : 'ENCRYPT + SEND'}<ArrowRight size={19} /></button><p className="panel-note">{connected ? 'Ready. Your message will be locked before sending.' : 'Click CONNECT above to start.'}</p></article>

            <article className={`wire-panel ${(busy === 'message' || (playing && step === 2)) ? 'transmitting' : ''}`}><div className="panel-top"><span className="mono">THE WIRE</span><span className="wire-tag mono">TCP</span></div><div className="wire-art" aria-hidden="true"><span className="wire-line" /><div className="wire-lock"><LockKeyhole size={24} strokeWidth={1.5} /></div><span className="data-packet packet-one" /><span className="data-packet packet-two" /></div><div className="wire-label mono">{activeAlgorithm}</div><div className="cipher-preview mono">{result ? hexBytes(result.record.ciphertext).slice(0, 24).map((b, i) => <span key={i}>{b}</span>) : <span className="cipher-placeholder">ENCRYPTED BYTES<br />WILL APPEAR HERE</span>}</div><div className="wire-footer mono"><span>{result ? `${result.record.wire_bytes} B ON THE WIRE` : 'AWAITING TRANSMISSION'}</span><span className="signal-bars" aria-hidden="true">▂▄▆</span></div></article>

            <article className={`endpoint receiver ${result && step === 4 ? 'verified' : ''}`}><div className="panel-top"><span className="mono">B / RECEIVER</span><span className="mini-tag">{result && step === 4 ? 'CHECKED' : 'UNLOCKED TEXT'}</span></div><div className="field-label">Same message. Nothing lost.</div><div className="received-message" aria-live="polite">{result && step === 4 ? <><span className="quote-mark">“</span><p>{result.text}</p></> : <div className="receiver-empty"><Fingerprint size={36} strokeWidth={1} /><p>{result ? 'Following the recorded transfer…' : 'Waiting for a checked message.'}</p></div>}</div><div className="verification-line mono">{result && step === 4 ? <><ShieldCheck size={17} /> MESSAGE CHECK PASSED</> : <><LockKeyhole size={15} /> CHECKED BEFORE DISPLAY</>}</div><p className="panel-note">Changed or repeated messages are rejected.</p></article>
          </div>

          <div className="metrics-row"><Metric label="TIME TO LOCK" value={result ? `${result.encryption_ms}` : '—'} unit="ms" /><Metric label="SEND + REPLY TIME" value={result ? `${result.round_trip_ms}` : '—'} unit="ms" /><Metric label="MESSAGE SIZE" value={result ? `${result.message_bytes}` : '—'} unit="bytes" /><Metric label="TAMPER CHECK" value={result ? 'PASSED' : 'PENDING'} accent={Boolean(result)} /></div>

          <section className="pipeline-section"><div className="subsection-heading"><div><span className="eyebrow">02 / UNDER THE HOOD</span><h3>Nothing up our sleeves.</h3></div><span className="mono subdued">{replay ? 'RECORDED TRANSFER / PLAYBACK' : 'FOLLOW THE DATA'}</span></div><div className="pipeline">{stages.map((stage, index) => <React.Fragment key={stage}><button className={`pipeline-step ${step === index ? 'current' : ''} ${result && step > index ? 'complete' : ''}`} disabled={!result || Boolean(busy)} onClick={() => { setStep(index); setReplay(true); setPlaying(false); }}><span className="step-number mono">0{index + 1}</span><span>{stage}</span>{result && step > index ? <Check size={15} /> : <span className="step-marker" />}</button>{index < 4 && <ArrowRight className="step-arrow" size={18} />}</React.Fragment>)}</div><div className="pipeline-details"><p>{step >= 0 ? stageNotes[step] : 'Send a message to inspect the real transfer, one step at a time. The animation is an explanation; the encryption is real.'}</p><div className="playback-controls"><button className="icon-button" title="Previous step" aria-label="Previous step" disabled={!result || step <= 0 || Boolean(busy)} onClick={() => { setStep(s => s - 1); setReplay(true); setPlaying(false); }}><ChevronLeft size={18} /></button><button className="button small" disabled={!result || Boolean(busy)} onClick={() => { if (step >= 4) setStep(0); setReplay(true); setPlaying(!playing); }}>{playing ? <Pause size={14} /> : <Play size={14} />}{playing ? 'PAUSE' : 'REPLAY'}</button><button className="icon-button" title="Next step" aria-label="Next step" disabled={!result || step >= 4 || Boolean(busy)} onClick={() => { setStep(s => s + 1); setReplay(true); setPlaying(false); }}><ChevronRight size={18} /></button><button className="speed-button mono" onClick={() => setSpeed(s => s === 1 ? 2 : 1)} aria-label={`Playback speed ${speed} times`}>{speed}×</button></div></div></section>

          {result && step >= 0 && <StageEvidence result={result} step={step} />}
          <div className="details-grid"><section className="inspector"><div className="subsection-heading"><h3><Terminal size={18} /> Record inspector</h3><span className="mini-tag">ACTUAL BYTES</span></div>{result ? <><WireInspector record={result.record} /><p className="microcopy">Ciphertext includes the JSON message envelope ({result.payload_bytes} B). Header and length are public; the header is authenticated.</p><button className="text-button" onClick={async () => { try { await navigator.clipboard.writeText(JSON.stringify(result.record, null, 2)); setCopied(true); window.setTimeout(() => setCopied(false), 2000); } catch { setError('Clipboard unavailable. You can select and copy the bytes directly.'); } }}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? 'COPIED' : 'COPY RECORD'}</button></> : <div className="inspector-empty"><span className="mono">[ NO RECORD YET ]</span><p>Nonce, ciphertext, and authentication tag.<br />Everything on the wire. No secret keys.</p></div>}</section><HandshakePanel handshake={session?.handshake} /></div>
        </>}

        {tab === 'files' && <section className="tool-section"><div className="tool-intro"><FileUp size={28} strokeWidth={1.5} /><h3>Big files. Small encrypted pieces.</h3><p>Each 64 KiB chunk gets its own nonce and authentication tag. The receiver verifies the complete file before making it available.</p></div><div className="file-layout"><div><button className="dropzone" disabled={Boolean(busy)} onClick={() => fileInput.current?.click()} onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); if (!busy) chooseFile(e.dataTransfer.files[0]); }}><FileUp size={36} strokeWidth={1.25} /><strong>{file ? file.name : 'Drop a file. Keep it private in transit.'}</strong><span className="mono">{file ? `${bytes(file.size)} / CLICK TO CHANGE` : 'OR CLICK TO BROWSE · ANY FILE TYPE · UP TO 10 MiB'}</span></button><input ref={fileInput} type="file" className="sr-only" aria-label="Choose file" onChange={e => chooseFile(e.target.files?.[0])} /><button className="button black full-width" disabled={disabled || !file} onClick={upload}>{busy === 'file' ? 'TRANSFERRING + VERIFYING…' : 'ENCRYPT + TRANSFER'}<ArrowUpRight size={18} /></button></div><div className="chunk-panel"><div className="panel-top mono"><span>CHUNK BY CHUNK</span><span>{progress.chunk} SENT</span></div><div className="chunk-grid" aria-hidden="true">{Array.from({ length: 40 }, (_, i) => <span key={i} className={transfer || (progress.total > 0 && i < progress.sent / progress.total * 40) ? 'chunk filled' : 'chunk'} />)}</div><progress aria-label="File transfer progress" value={transfer ? 1 : progress.sent} max={transfer ? 1 : progress.total || 1} /><p className="mono microcopy">{transfer ? 'ALL CHUNKS VERIFIED' : `${bytes(progress.sent)} / ${bytes(progress.total)}`}<br />Grid shows proportional progress, up to 40 tiles.</p></div></div>{transfer && <div className="file-result"><div className="success-heading"><ShieldCheck size={23} /><h3>Byte for byte. An exact match.</h3></div><dl className="hash-list"><dt>SOURCE SHA-256</dt><dd>{transfer.source_sha256}</dd><dt>RECEIVER SHA-256</dt><dd>{transfer.receiver_sha256}</dd></dl><div className="file-result-footer"><span className="mono">{transfer.chunks} CHUNKS / {transfer.duration_ms} ms / {transfer.throughput_mbps} MiB/s</span><a className="button black" href={`${API_BASE_URL}/api/files/${transfer.download_id}`} download><ArrowDownToLine size={17} />DOWNLOAD VERIFIED FILE</a></div></div>}<p className="microcopy">Temporary files belong to your session and expire with it. Hosted Python endpoints handle plaintext. Public demo: 3 files per session; CLI: up to 100 MiB.</p></section>}

        {tab === 'attacks' && <section className="tool-section"><div className="tool-intro"><ShieldCheck size={28} strokeWidth={1.5} /><h3>Trust is good. A failed attack is better.</h3><p>These controls change real protocol traffic on an isolated test connection. Your main messaging channel stays available.</p></div><div className="attack-grid">{[
          { mode: 'tamper', no: '01', title: 'Change one byte.', desc: 'Change a tiny piece of the locked message. The receiver’s tamper check should catch the change.', action: 'TAMPER WITH RECORD' },
          { mode: 'replay', no: '02', title: 'Send it twice.', desc: 'Send an accepted message again. The receiver spots the repeated message number and rejects it.', action: 'REPLAY A RECORD' },
          { mode: 'handshake', no: '03', title: 'Swap the key.', desc: 'Pretend to be the receiver by replacing its public key. The identity check should detect the imposter.', action: 'SUBSTITUTE A KEY' },
        ].map(item => <article className="attack-card" key={item.mode}><span className="attack-number">{item.no}</span><h3>{item.title}</h3><p>{item.desc}</p><button className="button" disabled={disabled} onClick={() => perform(item.mode, async () => { setAttackResult(null); setAttackResult(await api<AttackResult>('/api/attacks', jsonOptions({ mode: item.mode }))); })}>{busy === item.mode ? 'TESTING…' : item.action}<MoveUpRight size={16} /></button></article>)}</div>{attackResult && <div className="attack-result" role="status"><div className="attack-result-label"><ShieldCheck size={26} /><span>ATTACK REJECTED.</span></div><p className="mono">{attackResult.code}</p><p>{attackResult.mode === 'tamper' ? 'The modified record failed authenticated decryption. Its plaintext was never released.' : attackResult.mode === 'replay' ? 'The first record was accepted. The duplicate was rejected by the sequence check.' : 'The substituted public key invalidated the receiver’s signature. No application message was sent.'}</p>{attackResult.original && <div className="attack-compare"><div><span className="mono">ORIGINAL CIPHERTEXT / FIRST 16 BYTES</span><code>{hexBytes(attackResult.original.ciphertext).slice(0, 16).join(' ')}</code></div><div><span className="mono">TRANSMITTED / {attackResult.mode === 'tamper' ? 'ONE BIT FLIPPED' : 'IDENTICAL RECORD'}</span><code>{hexBytes(attackResult.transmitted!.ciphertext).slice(0, 16).map((b, i) => <span key={i} className={b !== hexBytes(attackResult.original!.ciphertext)[i] ? 'changed-byte' : ''}>{b} </span>)}</code></div></div>}</div>}</section>}

        {tab === 'benchmarks' && <section className="tool-section"><div className="benchmark-heading"><div className="tool-intro"><h3>Two algorithms. Actual measurements.</h3><p>Run both ciphers on the server with identical payloads. Five warm-up runs, then 40 measured iterations per size.</p></div><button className="button black" disabled={disabled} onClick={() => perform('benchmark', async () => setBenchmark(await api<Benchmark>('/api/benchmarks', jsonOptions({}))))}><RefreshCw size={16} />{busy === 'benchmark' ? 'MEASURING…' : 'RUN BENCHMARK'}</button></div>{benchmark ? <><div className="benchmark-charts">{algorithms.map(name => { const rows = benchmark.rows.filter(r => r.algorithm === name); const max = Math.max(...benchmark.rows.map(r => r.throughput_mbps)); return <article className="benchmark-chart" key={name}><h3>{name}</h3><span className="mono microcopy">ENCRYPTION THROUGHPUT / MiB PER SECOND</span>{rows.map(row => <div className="chart-row" key={row.size}><div className="mono"><span>{bytes(row.size)}</span><strong>{row.throughput_mbps}</strong></div><svg viewBox="0 0 400 22" role="img" aria-label={`${bytes(row.size)}: ${row.throughput_mbps} MiB per second`}><rect width="400" height="22" fill="#e4e0d8" /><rect width={row.throughput_mbps / max * 400} height="22" fill={name === algorithms[0] ? '#151515' : '#a2cf38'} /></svg></div>)}</article>; })}</div><div className="table-scroll"><table><caption className="sr-only">Measured algorithm performance</caption><thead><tr><th>ALGORITHM</th><th>PAYLOAD</th><th>ENCRYPT / ms</th><th>DECRYPT / ms</th><th>P95 ENCRYPT / ms</th></tr></thead><tbody>{benchmark.rows.map(row => <tr key={`${row.algorithm}${row.size}`}><td>{row.algorithm}</td><td>{bytes(row.size)}</td><td>{row.encrypt_ms}</td><td>{row.decrypt_ms}</td><td>{row.p95_encrypt_ms}</td></tr>)}</tbody></table></div><div className="benchmark-footer"><span className="mono microcopy">{benchmark.platform} / {benchmark.machine} / PYTHON {benchmark.python}<br />CRYPTOGRAPHY {benchmark.cryptography} / {new Date(benchmark.timestamp * 1000).toLocaleString()}</span><button className="button" onClick={downloadCSV}><ArrowDownToLine size={15} />EXPORT CSV</button></div><p className="microcopy">{benchmark.scope} Results are cached for 60 seconds to bound public-demo load.</p></> : <div className="benchmark-empty"><span className="big-outline">0 → 1</span><p>Measure first. Draw conclusions second.</p><span className="mono microcopy">CONNECT YOUR SESSION, THEN RUN THE BENCHMARK.</span></div>}</section>}

        {tab === 'guide' && <Guide />}

        <section className="event-strip"><div className="event-title mono"><span className={`status-dot ${streamLive ? 'live' : ''}`} />{streamLive ? 'LIVE EVENT FEED' : 'EVENT FEED'}</div><p className="mono">{lastEvent ? `${new Date(lastEvent.timestamp || Date.now()).toLocaleTimeString()} / ${lastEvent.stage.toUpperCase().replaceAll('_', ' ')}` : 'No events yet. Establish a connection to begin.'}</p><span className="mono event-count">{events.length.toString().padStart(2, '0')} EVENTS</span></section>
      </section>

      <section className="bottom-callout"><div><span className="eyebrow">THE PRINCIPLE IS SIMPLE.</span><h2>Readable at the ends.<br />Unrecognizable in between.</h2></div><button className="round-link" aria-label="Read how the protocol works" onClick={() => { setTab('guide'); document.getElementById('workspace')?.scrollIntoView({ behavior: 'smooth' }); }}><ArrowUpRight size={36} strokeWidth={1.3} /></button></section>
    </main>
    <footer><span className="footer-brand">SECURENET / LAB</span><p>Educational protocol. Hosted endpoints can access demo plaintext.<br />Browser ↔ server: HTTPS in deployment. Sender ↔ receiver: authenticated TCP encryption.</p><span className="mono">LESS MAGIC.<br />MORE UNDERSTANDING.</span></footer>
  </>;
}

function Metric({ label, value, unit, accent }: { label: string; value: string; unit?: string; accent?: boolean }) {
  return <div className={`metric ${accent ? 'metric-success' : ''}`}><span className="mono metric-label">{label}</span><div>{accent && <Check size={20} />}<strong>{value}</strong>{unit && <span className="mono">{unit}</span>}</div></div>;
}

function StageEvidence({ result, step }: { result: Message; step: number }) {
  const view = [
    ['YOUR TEXT', result.text, 'UTF-8 BYTES / FIRST 512', hexBytes(result.plaintext_hex).join(' ')],
    ['WHAT GOES INTO THE LOCK', `${result.payload_bytes} bytes (message + its label)\nOne-time number: ${result.record.nonce}\nSecret key: stays inside the sender`, 'LOCKED DATA / FIRST 64 BYTES', hexBytes(result.record.ciphertext).slice(0, 64).join(' ')],
    ['WHAT THE NETWORK CARRIES', `Message number: ${result.record.sequence}\nDelivery details + locked data + tamper check\nTotal: ${result.record.wire_bytes} bytes`, 'THE RECEIVER REPLIED', `The receiver accepted the message.\nSend + reply time: ${result.round_trip_ms} ms`],
    ['TAMPER-CHECK VALUE (TAG)', result.record.tag, 'CHECKS PASSED', 'Correct message number.\nNo changes detected.\nAccepted on this connection.'],
    ['VERIFIED LOCKED DATA / FIRST 32 BYTES', hexBytes(result.record.ciphertext).slice(0, 32).join(' '), 'YOUR READABLE MESSAGE', result.text],
  ][step];
  return <div className="stage-evidence"><div><span className="mono">{view[0]}</span><pre>{view[1]}</pre></div><ArrowRight size={20} /><div><span className="mono">{view[2]}</span><pre>{view[3]}</pre></div></div>;
}

function WireInspector({ record }: { record: WireRecord }) {
  return <dl className="record-list"><dt>MESSAGE NUMBER</dt><dd>{record.sequence.toString().padStart(6, '0')}</dd><dt>ONE-TIME NUMBER<br />(NONCE)</dt><dd>{record.nonce}</dd><dt>DELIVERY DETAILS<br />(HEADER)</dt><dd>{record.header}</dd><dt>LOCKED DATA<br />(CIPHERTEXT)</dt><dd className="ciphertext-value">{hexBytes(record.ciphertext).join(' ')}{record.truncated && ' … [first 512 bytes]'}</dd><dt>TAMPER CHECK<br />(TAG)</dt><dd className="tag-value">{record.tag}</dd></dl>;
}

function HandshakePanel({ handshake }: { handshake?: Handshake }) {
  return <section className="handshake-panel"><div className="subsection-heading"><h3><KeyRound size={18} /> The key to the secret</h3><span className="mini-tag">{handshake ? 'AUTHENTICATED' : 'X25519'}</span></div><p>Both ends derive their keys independently.<br />The secret itself never crosses the wire.</p><div className="handshake-diagram"><div className="handshake-peers"><span><LockKeyhole size={20} />SENDER<br /><small>PRIVATE KEY STAYS HERE</small></span><span className="exchange-arrows">⇄<small>PUBLIC KEYS</small></span><span><LockKeyhole size={20} />RECEIVER<br /><small>PRIVATE KEY STAYS HERE</small></span></div><ArrowDown size={18} /><div className="derivation mono">VERIFY ED25519 SIGNATURES</div><ArrowDown size={18} /><div className="derivation mono">X25519 → HKDF-SHA256</div><ArrowDown size={18} /><div className={`derived-key mono ${handshake ? 'ready' : ''}`}><KeyRound size={15} /> DIRECTIONAL SESSION KEYS</div></div><details><summary className="mono"><Fingerprint size={15} /> INSPECT PUBLIC IDENTITIES <ChevronRight size={14} /></summary>{handshake ? <dl className="record-list"><dt>SENDER FINGERPRINT / SHA-256</dt><dd>{handshake.sender_fingerprint}</dd><dt>RECEIVER FINGERPRINT / SHA-256</dt><dd>{handshake.receiver_fingerprint}</dd><dt>SENDER EPHEMERAL PUBLIC KEY</dt><dd>{handshake.sender_public}</dd><dt>RECEIVER EPHEMERAL PUBLIC KEY</dt><dd>{handshake.receiver_public}</dd><dt>HANDSHAKE DURATION</dt><dd>{handshake.duration_ms} ms</dd></dl> : <p className="microcopy">Connect to inspect real public keys and pinned identity fingerprints.</p>}</details></section>;
}

function Guide() {
  return <section className="tool-section guide"><div className="tool-intro"><CircleHelp size={28} strokeWidth={1.5} /><h3>Start with the simple words.</h3><p>Encryption locks data. Decryption unlocks it. Hashing makes a fingerprint you can compare.</p></div><div className="plain-language"><h3>A small dictionary</h3><dl>{[
    ['Plaintext', 'Your original, readable message.'], ['Ciphertext', 'The locked version of your message.'],
    ['Secret key', 'The value used to lock and unlock a message.'], ['Hash / digest', 'A fixed-length digital fingerprint of some data.'],
    ['MD5', 'Message Digest 5: an older hash with 32 hexadecimal characters.'], ['SHA-256', 'Secure Hash Algorithm, 256-bit: a modern hash with 64 hexadecimal characters.'],
    ['Nonce', 'A one-time number used when locking a message.'], ['Tag', 'A tamper-check value that helps detect changes to locked data.'],
    ['Handshake', 'The setup step where the two computers check identities and agree on secret keys.'],
  ].map(([word, meaning]) => <React.Fragment key={word}><dt>{word}</dt><dd>{meaning}</dd></React.Fragment>)}</dl></div>{[
    ['01', 'How do MD5 and SHA-256 work here?', 'Type some text in Hashing and Python calculates both fingerprints. Change one letter and compare the highlighted differences. The output length stays fixed, even if you type more text. Identical input always produces the same hash.'],
    ['02', 'Can I decrypt a hash?', 'No. A hash is a one-way fingerprint, not a locked copy of the text. Someone can still guess an input and check its hash, so hashing alone does not keep a message secret. Use encryption when the receiver needs to recover the original message.'],
    ['03', 'Which hash should I use?', 'MD5 is here to explain an older algorithm. People can deliberately create different data with the same MD5 hash, so it is unsuitable for security checks. SHA-256 is a modern choice for comparing files with a trusted expected fingerprint.'],
    ['04', 'How is a message locked and unlocked?', 'The two Python computers check each other’s identity and agree on secret keys. AES or ChaCha20 locks the message before sending it over the network. The receiver checks for changes, then reveals the message with the right key. The website controls these hosted computers, which can see your demo text.'],
    ['05', 'What catches a changed or repeated message?', 'The tamper-check value catches changes to locked data. Message numbers catch repeats. This adds protection that a plain MD5 or SHA-256 fingerprint alone cannot provide. You can try both attacks in the Attacks tab.'],
    ['06', 'What do the speed numbers mean?', 'Time to lock measures encryption. Send + reply time includes the network trip and the receiver’s checks. Benchmarks compares encryption speeds. The replay animation is slowed down to help you learn; it is not a timer.'],
    ['07', 'How can I see the actual network traffic?', 'Wireshark is a network traffic viewer. For a local CLI demonstration, capture your loopback interface and filter with tcp.port == 9000. Follow the TCP stream and compare it with your text. See docs/wireshark-guide.md for the steps.'],
  ].map(([no, title, body]) => <article className="guide-entry" key={no}><span className="mono">{no}</span><div><h3>{title}</h3><p>{body}</p></div></article>)}<div className="cli-guide"><span className="eyebrow">TAKE IT TO THE TERMINAL</span><pre><code>{'securenet init\nsecurenet receiver\n\n# In another terminal\nsecurenet send "Meet me on the other side."\nsecurenet file ./sample.pdf ./verified.pdf\nsecurenet benchmark'}</code></pre><p className="microcopy">The CLI and website share the same cryptography and TCP protocol. See the README for setup and two-machine identity provisioning.</p></div></section>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
