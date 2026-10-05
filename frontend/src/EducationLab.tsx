import { useState } from 'react';
import { ArrowRight, Check, LockKeyhole, ShieldCheck } from 'lucide-react';
import './education.css';

type Props = { busy: boolean; run: (action: () => Promise<void>) => Promise<void> };

export function EducationLab({ busy, run }: Props) {
  const [technique, setTechnique] = useState('caesar');
  const [text, setText] = useState('HELLO NETWORK');
  const [key, setKey] = useState('KEY');
  const [shift, setShift] = useState('3');
  const [result, setResult] = useState<Record<string, string | boolean> | null>(null);
  async function calculate() {
    await run(async () => {
      const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/education/demo`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ technique, text, key, shift: Number(shift) }) });
      const data = await response.json(); if (!response.ok) throw new Error(data.detail || 'Educational demo failed.'); setResult(data);
    });
  }
  return <section className="tool-section education-lab"><div className="tool-intro"><span className="eyebrow">EDUCATIONAL ONLY / NOT MODERN SECURITY</span><h3>Old ideas. Clear lessons.</h3><p>See how classical ciphers move letters and bits. Then compare them with public-key ideas. Use AES-GCM and ChaCha20-Poly1305 for real secure data.</p></div><div className="education-layout"><div className="education-controls"><label>Technique<select value={technique} onChange={event => { setTechnique(event.target.value); setResult(null); }}><option value="caesar">Caesar cipher</option><option value="vigenere">Vigenère cipher</option><option value="xor">XOR</option><option value="rsa">RSA-OAEP</option><option value="ed25519">Ed25519 signature</option><option value="ecc">ECC / X25519 explanation</option></select></label><label>Text<textarea value={text} onChange={event => { setText(event.target.value); setResult(null); }} maxLength={4096} /></label>{technique === 'caesar' && <label>Shift<input type="number" value={shift} onChange={event => setShift(event.target.value)} /></label>}{['vigenere', 'xor'].includes(technique) && <label>Key<input value={key} onChange={event => setKey(event.target.value)} maxLength={128} /></label>}<button className="button black" disabled={busy || !text} onClick={() => void calculate()}>RUN DEMO <ArrowRight size={17} /></button></div><div className="education-flow"><div className="education-node"><span className="mono">INPUT</span><strong>{text || '(empty)'}</strong></div><ArrowRight size={19} /><div className="education-node dark"><LockKeyhole size={20} /><span className="mono">{technique.toUpperCase()}</span><strong>{result ? String(result.encrypted || result.ciphertext || result.signature || result.message || 'VERIFIED') : 'WAITING'}</strong></div><ArrowRight size={19} /><div className="education-node verified"><Check size={20} /><span className="mono">OUTPUT</span><strong>{result ? String(result.decrypted || result.decoded || (result.verified ? 'SIGNATURE VERIFIED' : result.message || 'SEE BELOW')) : 'WAITING'}</strong></div></div></div>{result && <div className="education-result"><div className="result-title"><ShieldCheck size={21} /><strong>{String(result.technique)} / {result.educational_only ? 'EDUCATIONAL ONLY' : ''}</strong></div><pre>{JSON.stringify(result, null, 2)}</pre></div>}<div className="algorithm-lesson"><article><h3>RSA</h3><p>Public-key encryption: anyone can use the public key to lock a short message. Only the private key can unlock it. Real systems usually use hybrid encryption for files.</p></article><article><h3>ECC / X25519</h3><p>Key exchange, not file encryption. Two endpoints derive the same session material without sending the secret itself.</p></article><article><h3>Ed25519</h3><p>Digital signatures prove that a private identity signed a message. They do not hide the message.</p></article></div></section>;
}
