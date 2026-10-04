import { useState } from 'react';
import { ArrowRight, Check, Fingerprint, Hash, LockKeyhole } from 'lucide-react';
import './hashing.css';

type HashRow = {
  algorithm: string; bits: number; hex_characters: number;
  original: string; changed: string; changed_bits: number; matching: boolean;
};

export type HashComparison = {
  original_bytes: number; changed_bytes: number;
  original_hex: string; changed_hex: string; identical_input: boolean; rows: HashRow[];
};

type Props = {
  connected: boolean;
  busy: boolean;
  run: (action: () => Promise<void>) => Promise<void>;
  compare: (original: string, changed: string) => Promise<HashComparison>;
};

const hex = (value: string) => value.match(/.{1,2}/g)?.join(' ') || '(no bytes — empty text)';

export function HashLab({ connected, busy, run, compare }: Props) {
  const [original, setOriginal] = useState('Hello');
  const [changed, setChanged] = useState('hello');
  const [result, setResult] = useState<HashComparison | null>(null);
  const [step, setStep] = useState(0);
  const originalSize = new TextEncoder().encode(original).length;
  const changedSize = new TextEncoder().encode(changed).length;
  const tooLarge = Math.max(originalSize, changedSize) > 8192;

  function edit(which: 'original' | 'changed', value: string) {
    if (which === 'original') setOriginal(value); else setChanged(value);
    setResult(null);
    setStep(0);
  }

  async function submit() {
    setResult(null);
    await run(async () => {
      const next = await compare(original, changed);
      setResult(next);
      setStep(2);
    });
  }

  return <section className="tool-section hash-lab">
    <div className="hash-intro">
      <div className="tool-intro">
        <Fingerprint size={28} strokeWidth={1.5} />
        <h3>Same text. Same fingerprint.</h3>
        <p>A <strong>hash</strong> is a fixed-length digital fingerprint of your data. Try MD5 and SHA-256 below: changing just one letter usually changes many parts of the fingerprint.</p>
      </div>
      <div className="hash-definition"><span className="eyebrow">ONE WAY ONLY</span><p>Text → hash</p><span>A hash cannot be decrypted back into your text. It does not keep the text secret.</span></div>
    </div>

    <div className="hash-inputs">
      <div><label className="field-label" htmlFor="hash-original">Original text</label><textarea id="hash-original" value={original} maxLength={8192} disabled={busy} onChange={e => edit('original', e.target.value)} spellCheck={false} /><span className="mono microcopy">{originalSize} BYTES</span></div>
      <div><label className="field-label" htmlFor="hash-changed">Changed text</label><textarea id="hash-changed" value={changed} maxLength={8192} disabled={busy} onChange={e => edit('changed', e.target.value)} spellCheck={false} /><span className="mono microcopy">{changedSize} BYTES</span></div>
    </div>
    <div className="hash-actions">
      <button className="button black" disabled={!connected || busy || tooLarge} onClick={submit}><Hash size={17} />{busy ? 'CALCULATING…' : 'COMPARE FINGERPRINTS'}<ArrowRight size={17} /></button>
      <button className="text-button" disabled={busy} onClick={() => edit('changed', original)}>USE THE SAME TEXT</button>
      <button className="text-button" disabled={busy} onClick={() => { setOriginal('Hello'); setChanged('hello'); setResult(null); setStep(0); }}>TRY Hello → hello</button>
    </div>
    <p className="microcopy" role={tooLarge ? 'alert' : undefined}>{tooLarge ? 'Please keep each text under 8 KiB (8,192 bytes).' : connected ? 'Empty text works too. Python calculates the real hashes on the web server; this exercise does not send a TCP message.' : 'Click CONNECT above to start the lab, then compare the two texts.'}</p>

    <div className="hash-journey" aria-label="How hashing works">
      {['Your text', 'Computer bytes', 'Digital fingerprint'].map((label, index) => <button key={label} className={step === index ? 'hash-stage selected' : 'hash-stage'} disabled={!result} aria-pressed={step === index} onClick={() => setStep(index)}><span className="mono">0{index + 1}</span><strong>{label}</strong>{index < 2 ? <ArrowRight size={16} /> : <Fingerprint size={18} />}</button>)}
    </div>
    <div className="hash-step-note">
      {!result ? <p>Calculate a fingerprint, then click the steps to follow your data.</p> : step === 0 ? <><span className="eyebrow">01 / START WITH YOUR TEXT</span><p>We use exactly what you typed, including spaces, capital letters, and line breaks.</p><div className="hash-byte-views"><pre>{original || '(empty text)'}</pre><pre>{changed || '(empty text)'}</pre></div></> : step === 1 ? <><span className="eyebrow">02 / TURN LETTERS INTO BYTES</span><p>UTF-8 is how the computer represents your letters as numbers. Below are the first 64 bytes, written in hexadecimal (base 16).</p><div className="hash-byte-views"><pre>{hex(result.original_hex)}</pre><pre>{hex(result.changed_hex)}</pre></div></> : <><span className="eyebrow">03 / CALCULATE THE FINGERPRINT</span><p>MD5 always returns 32 hexadecimal characters. SHA-256 always returns 64. Each character represents 4 bits — four tiny 0-or-1 values.</p></>}
    </div>

    <div className="hash-results" aria-live="polite">
      {result ? result.rows.map(row => <HashCard key={row.algorithm} row={row} identical={result.identical_input} />) : <div className="hash-empty"><Hash size={30} strokeWidth={1.25} /><p>Your fingerprints will appear here.</p><span className="mono">MD5 / 128 BITS &nbsp; · &nbsp; SHA-256 / 256 BITS</span></div>}
    </div>

    <div className="hash-lesson">
      <article><Fingerprint size={23} /><h3>Hashing = make a fingerprint</h3><p>MD5 and SHA-256 help compare data. To check a downloaded file, compare its SHA-256 with a fingerprint from a trusted source. A plain hash alone does not prove who sent it.</p></article>
      <article><LockKeyhole size={23} /><h3>Encryption = lock a message</h3><p>AES locks data with a secret key. The receiver uses the right key to unlock it. Try this reversible process in the <strong>Messages</strong> tab.</p></article>
    </div>
    <p className="microcopy">MD5 is included as a learning example. Different inputs can deliberately be made to share an MD5 fingerprint (a collision), so it is unsuitable for security checks. SHA-256 is the modern choice for file fingerprints. Neither is a password-storage scheme on its own.</p>
  </section>;
}

function HashCard({ row, identical }: { row: HashRow; identical: boolean }) {
  return <article className="hash-card" aria-label={`${row.algorithm} results`}>
    <div className="hash-card-heading"><h3>{row.algorithm}</h3><span className={`mini-tag ${row.algorithm === 'SHA-256' ? 'hash-modern' : ''}`}>{row.algorithm === 'MD5' ? 'OLDER / LEARNING EXAMPLE' : 'MODERN FILE FINGERPRINT'}</span></div>
    <span className="mono microcopy">{row.bits} BITS / {row.hex_characters} HEX CHARACTERS</span>
    <dl className="hash-digests"><dt>ORIGINAL TEXT’S FINGERPRINT</dt><dd className="original-digest">{row.original}</dd><dt>CHANGED TEXT’S FINGERPRINT</dt><dd className="changed-digest" aria-label={`Changed fingerprint: ${row.changed}`}>{[...row.changed].map((character, index) => <span key={index} className={character !== row.original[index] ? 'hash-difference' : ''}>{character}</span>)}</dd></dl>
    <div className="hash-change-count"><strong>{row.changed_bits}<small> / {row.bits}</small></strong><span className="mono">BITS CHANGED</span>{row.matching && <Check size={21} />}</div>
    <progress value={row.changed_bits} max={row.bits} aria-label={`${row.algorithm}: ${row.changed_bits} of ${row.bits} bits changed`} />
    <p className="microcopy">{identical ? 'Same input, same result. Hashing is repeatable.' : row.matching ? 'Different inputs produced the same hash: a collision. Equal fingerprints do not prove the inputs are identical.' : 'Highlighted characters differ. A tiny input change can affect many output bits — the avalanche effect.'}</p>
  </article>;
}
