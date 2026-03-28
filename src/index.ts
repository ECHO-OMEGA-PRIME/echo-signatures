/**
 * Echo Signatures v2.0.0
 * E-signature platform with Stripe credit-based billing
 * Cloudflare Worker — D1 + KV + Stripe + Service Bindings
 */

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  SHARED_BRAIN: Fetcher;
  EMAIL_SENDER: Fetcher;
  ECHO_API_KEY: string;
  ENVIRONMENT: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  SIGNATURE_HMAC_KEY?: string;
  ANALYTICS: AnalyticsEngineDataset;
}

interface RLState { c: number; t: number; }

function sanitize(s: string | null | undefined, max = 2000): string {
  if (!s) return '';
  return s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').trim().slice(0, max);
}

function uid(): string { return crypto.randomUUID().replace(/-/g, '').slice(0, 16); }
function slug8(): string { return Array.from(crypto.getRandomValues(new Uint8Array(6))).map(b => b.toString(36).padStart(2, '0')).join('').slice(0, 10); }
function token32(): string { return Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join(''); }

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'X-XSS-Protection': '1; mode=block', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' } });
}

function slog(level: 'info' | 'warn' | 'error', msg: string, data?: Record<string, unknown>) {
  const entry = { ts: new Date().toISOString(), level, worker: 'echo-signatures', version: '2.0.0', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}

function cors(): Response {
  return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,X-Echo-API-Key,X-Tenant-ID,Authorization', 'Access-Control-Max-Age': '86400' } });
}

function authOk(req: Request, env: Env): boolean {
  const expected = env.ECHO_API_KEY;
  if (!expected) return false;
  const apiKey = req.headers.get('X-Echo-API-Key') || '';
  const bearer = (req.headers.get('Authorization') || '').replace('Bearer ', '');
  return apiKey === expected || bearer === expected;
}
function tid(req: Request): string { return req.headers.get('X-Tenant-ID') || new URL(req.url).searchParams.get('tenant_id') || 'default'; }

async function rateLimit(env: Env, key: string, max: number, windowSec: number): Promise<boolean> {
  const raw = await env.CACHE.get<RLState>(`rl:${key}`, 'json');
  const now = Math.floor(Date.now() / 1000);
  if (!raw || (now - raw.t) > windowSec) { await env.CACHE.put(`rl:${key}`, JSON.stringify({ c: 1, t: now }), { expirationTtl: windowSec * 2 }); return true; }
  const elapsed = now - raw.t;
  const decay = (elapsed / windowSec) * max;
  const current = Math.max(0, raw.c - decay) + 1;
  await env.CACHE.put(`rl:${key}`, JSON.stringify({ c: current, t: now }), { expirationTtl: windowSec * 2 });
  return current <= max;
}

const CREDIT_PACKS = [
  { id: 'starter', name: 'Starter', credits: 10, price: 999, display: '$9.99' },
  { id: 'professional', name: 'Professional', credits: 50, price: 3999, display: '$39.99' },
  { id: 'business', name: 'Business', credits: 200, price: 12999, display: '$129.99' },
  { id: 'enterprise', name: 'Enterprise', credits: 1000, price: 49999, display: '$499.99' },
] as const;

async function verifyStripeSignature(payload: string, sigHeader: string, secret: string): Promise<boolean> {
  const parts: Record<string, string> = {};
  for (const p of sigHeader.split(',')) {
    const eq = p.indexOf('=');
    if (eq > 0) parts[p.slice(0, eq).trim()] = p.slice(eq + 1).trim();
  }
  const ts = parts['t'];
  const v1 = parts['v1'];
  if (!ts || !v1) return false;
  if (Math.abs(Date.now() / 1000 - parseInt(ts)) > 300) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${ts}.${payload}`));
  const expected = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (expected.length !== v1.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ v1.charCodeAt(i);
  return diff === 0;
}

function signingPageHtml(envelope: Record<string, unknown>, signer: Record<string, unknown>, fields: Record<string, unknown>[], tenant: Record<string, unknown> | null): string {
  const brandColor = (tenant?.brand_color as string) || '#14b8a6';
  const logoUrl = tenant?.logo_url as string || '';
  const logoHtml = logoUrl ? `<img src="${logoUrl}" alt="" style="max-height:40px;margin-bottom:16px">` : '';
  const fieldsHtml = fields.filter(f => f.signer_id === signer.id || !f.signer_id).map(f => {
    if (f.type === 'signature') return `<div class="field"><label>${f.label || 'Signature'} *</label><canvas id="sig-${f.id}" width="400" height="120" style="border:1px solid #1e293b;border-radius:8px;background:#0f172a;cursor:crosshair"></canvas><button type="button" onclick="clearSig('${f.id}')" style="font-size:12px;color:#94a3b8;margin-top:4px;background:none;border:none;cursor:pointer">Clear</button><input type="hidden" name="field_${f.id}" id="val-${f.id}"></div>`;
    if (f.type === 'initials') return `<div class="field"><label>${f.label || 'Initials'} *</label><canvas id="sig-${f.id}" width="200" height="80" style="border:1px solid #1e293b;border-radius:8px;background:#0f172a;cursor:crosshair"></canvas><button type="button" onclick="clearSig('${f.id}')" style="font-size:12px;color:#94a3b8;margin-top:4px;background:none;border:none;cursor:pointer">Clear</button><input type="hidden" name="field_${f.id}" id="val-${f.id}"></div>`;
    if (f.type === 'text') return `<div class="field"><label>${f.label || 'Text'}${f.required ? ' *' : ''}</label><input name="field_${f.id}" type="text" maxlength="500" ${f.required ? 'required' : ''}></div>`;
    if (f.type === 'date') return `<div class="field"><label>${f.label || 'Date'}${f.required ? ' *' : ''}</label><input name="field_${f.id}" type="date" ${f.required ? 'required' : ''}></div>`;
    if (f.type === 'checkbox') return `<div class="field" style="flex-direction:row;gap:8px;align-items:center"><input name="field_${f.id}" type="checkbox" id="cb-${f.id}" ${f.required ? 'required' : ''}><label for="cb-${f.id}" style="margin:0">${f.label || 'I agree'}</label></div>`;
    return '';
  }).join('');

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign: ${sanitize(envelope.title as string, 100)}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#0a0f1a;color:#e2e8f0;min-height:100vh;display:flex;justify-content:center;padding:24px}
.wrap{max-width:560px;width:100%}.card{background:#0c1220;border:1px solid #1e293b;border-radius:16px;padding:32px;margin-bottom:16px}
h1{font-size:22px;font-weight:800;margin-bottom:4px}
.sub{color:#94a3b8;font-size:14px;margin-bottom:16px}
.msg{background:#0f172a;border-radius:8px;padding:16px;margin-bottom:20px;font-size:14px;color:#94a3b8;line-height:1.5}
.field{display:flex;flex-direction:column;margin-bottom:16px}
label{font-size:13px;color:#94a3b8;margin-bottom:4px}
input[type="text"],input[type="date"]{padding:10px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;color:#e2e8f0;font-size:14px;outline:none}
input:focus{border-color:${brandColor}}
.actions{display:flex;gap:12px;margin-top:20px}
.btn{flex:1;padding:14px;border:none;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer}
.btn-sign{background:${brandColor};color:#fff}.btn-sign:hover{opacity:0.9}
.btn-decline{background:#1e293b;color:#94a3b8}.btn-decline:hover{background:#334155}
.result{text-align:center;padding:20px}.ok{color:#6ee7b7}.err{color:#fca5a5}
.badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;margin-bottom:12px;background:${brandColor}22;color:${brandColor}}
</style></head><body>
<div class="wrap">
<div class="card">
${logoHtml}
<span class="badge">Document Signing</span>
<h1>${sanitize(envelope.title as string, 200)}</h1>
<p class="sub">Signing as: ${sanitize(signer.name as string, 100)} (${sanitize(signer.email as string, 200)})</p>
${envelope.message ? `<div class="msg">${sanitize(envelope.message as string, 2000)}</div>` : ''}
<form id="signForm">
${fieldsHtml}
<div class="actions">
<button type="submit" class="btn btn-sign">Sign Document</button>
<button type="button" class="btn btn-decline" onclick="declineDoc()">Decline</button>
</div>
</form>
<div id="result" class="result" style="display:none"></div>
</div>
<div style="text-align:center;font-size:11px;color:#475569">Powered by Echo Signatures &bull; Legally binding e-signature with audit trail</div>
</div>
<script>
const canvases={};
document.querySelectorAll('canvas').forEach(c=>{const ctx=c.getContext('2d');ctx.strokeStyle='#e2e8f0';ctx.lineWidth=2;ctx.lineCap='round';let drawing=false;let lx,ly;
const fid=c.id.replace('sig-','');canvases[fid]={canvas:c,ctx,hasData:false};
function pos(e){const r=c.getBoundingClientRect();const t=e.touches?e.touches[0]:e;return{x:t.clientX-r.left,y:t.clientY-r.top}}
c.addEventListener('mousedown',e=>{drawing=true;const p=pos(e);lx=p.x;ly=p.y});
c.addEventListener('touchstart',e=>{e.preventDefault();drawing=true;const p=pos(e);lx=p.x;ly=p.y},{passive:false});
function draw(e){if(!drawing)return;const p=pos(e);ctx.beginPath();ctx.moveTo(lx,ly);ctx.lineTo(p.x,p.y);ctx.stroke();lx=p.x;ly=p.y;canvases[fid].hasData=true}
c.addEventListener('mousemove',draw);c.addEventListener('touchmove',e=>{e.preventDefault();draw(e)},{passive:false});
c.addEventListener('mouseup',()=>drawing=false);c.addEventListener('mouseleave',()=>drawing=false);
c.addEventListener('touchend',()=>drawing=false);});
function clearSig(fid){const d=canvases[fid];if(d){d.ctx.clearRect(0,0,d.canvas.width,d.canvas.height);d.hasData=false}}
document.getElementById('signForm').onsubmit=async e=>{e.preventDefault();
const fd=new FormData(e.target);const data={};
for(const[k,v]of fd.entries())data[k]=v;
for(const[fid,d]of Object.entries(canvases)){if(d.hasData)data['field_'+fid]=d.canvas.toDataURL('image/png')}
// Validate signatures
let valid=true;for(const[fid,d]of Object.entries(canvases)){if(!d.hasData){valid=false;break}}
if(!valid){alert('Please complete all signature fields');return}
try{const r=await fetch('/sign/${signer.token}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
const j=await r.json();const el=document.getElementById('result');el.style.display='block';
if(r.ok){el.innerHTML='<h2 class="ok">Document Signed Successfully</h2><p style="color:#94a3b8;margin-top:8px">'+( j.message||'Thank you!')+'</p>';e.target.style.display='none'}
else{el.innerHTML='<p class="err">'+(j.error||'Failed')+'</p>'}}catch(err){document.getElementById('result').innerHTML='<p class="err">Network error</p>'}};
function declineDoc(){const reason=prompt('Reason for declining (optional):');
fetch('/decline/${signer.token}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})})
.then(r=>r.json()).then(j=>{const el=document.getElementById('result');el.style.display='block';
el.innerHTML='<h2 style="color:#fbbf24">Document Declined</h2><p style="color:#94a3b8;margin-top:8px">The sender has been notified.</p>';
document.getElementById('signForm').style.display='none'}).catch(()=>alert('Failed'))}
</script></body></html>`;
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (req.method === 'OPTIONS') return cors();

    const url = new URL(req.url);
    const p = url.pathname;
    const m = req.method;
    const ip = req.headers.get('CF-Connecting-IP') || '0.0.0.0';

    // ── Public: Root + Health ──
    if (p === '/') return json({ service: 'echo-signatures', version: '2.0.0', status: 'operational', features: ['e-signatures', 'templates', 'bulk-send', 'stripe-credits', 'audit-trail', 'sequential-signing'] });
    if (p === '/health') {
      const r = await env.DB.prepare('SELECT COUNT(*) as c FROM envelopes').first<{ c: number }>();
      return json({ status: 'healthy', service: 'echo-signatures', version: '2.0.0', envelopes: r?.c || 0, stripe: !!env.STRIPE_SECRET_KEY });
    }

    try {
    // ── Public: Signing Page (GET /sign/:token) ──
    if (m === 'GET' && p.startsWith('/sign/')) {
      const signerToken = p.split('/')[2];
      if (!signerToken) return json({ error: 'Missing token' }, 400);

      const signer = await env.DB.prepare('SELECT * FROM signers WHERE token = ?').bind(signerToken).first();
      if (!signer) return json({ error: 'Invalid signing link' }, 404);
      if (signer.status === 'signed') return new Response('<html><body style="background:#0a0f1a;color:#6ee7b7;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1>Already Signed</h1><p style="color:#94a3b8">This document was signed on ' + signer.signed_at + '</p></div></body></html>', { headers: { 'Content-Type': 'text/html' } });
      if (signer.status === 'declined') return new Response('<html><body style="background:#0a0f1a;color:#fbbf24;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1>Declined</h1><p style="color:#94a3b8">This document was declined.</p></div></body></html>', { headers: { 'Content-Type': 'text/html' } });

      const envelope = await env.DB.prepare('SELECT * FROM envelopes WHERE id = ?').bind(signer.envelope_id).first();
      if (!envelope) return json({ error: 'Envelope not found' }, 404);

      // Check expiry
      if (envelope.expires_at && new Date(envelope.expires_at as string) < new Date()) {
        return new Response('<html><body style="background:#0a0f1a;color:#fca5a5;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1>Expired</h1><p style="color:#94a3b8">This signing request has expired.</p></div></body></html>', { headers: { 'Content-Type': 'text/html' } });
      }

      // Check sequential order
      if (envelope.sequential) {
        const earlier = await env.DB.prepare('SELECT COUNT(*) as c FROM signers WHERE envelope_id = ? AND order_num < ? AND status != "signed"').bind(envelope.id, signer.order_num).first();
        if ((earlier?.c as number) > 0) {
          return new Response('<html><body style="background:#0a0f1a;color:#fbbf24;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1>Not Your Turn</h1><p style="color:#94a3b8">Previous signers must complete signing first.</p></div></body></html>', { headers: { 'Content-Type': 'text/html' } });
        }
      }

      const tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(envelope.tenant_id).first();
      const fields = await env.DB.prepare('SELECT * FROM fields WHERE envelope_id = ? ORDER BY page, id').bind(envelope.id).all();

      // Track view (ctx.waitUntil to prevent data loss)
      ctx.waitUntil((async () => {
        try {
          await env.DB.batch([
            env.DB.prepare('UPDATE signers SET status = CASE WHEN status = "pending" OR status = "sent" THEN "opened" ELSE status END, opened_at = COALESCE(opened_at, datetime("now")), last_viewed_at = datetime("now"), view_count = view_count + 1 WHERE id = ?').bind(signer.id),
            env.DB.prepare('INSERT INTO audit_trail (envelope_id, tenant_id, signer_id, action, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)').bind(envelope.id, envelope.tenant_id, signer.id, 'viewed', ip, sanitize(req.headers.get('User-Agent'), 500)),
          ]);
        } catch (_) { /* non-blocking */ }
      })());

      return new Response(signingPageHtml(envelope as Record<string, unknown>, signer as Record<string, unknown>, fields.results as Record<string, unknown>[], tenant as Record<string, unknown> | null), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // ── Public: Submit Signature (POST /sign/:token) ──
    if (m === 'POST' && p.startsWith('/sign/')) {
      const signerToken = p.split('/')[2];
      if (!(await rateLimit(env, `sign:${ip}`, 10, 3600))) return json({ error: 'Rate limited' }, 429);

      const signer = await env.DB.prepare('SELECT * FROM signers WHERE token = ?').bind(signerToken).first();
      if (!signer) return json({ error: 'Invalid token' }, 404);
      if (signer.status === 'signed') return json({ error: 'Already signed' }, 409);
      if (signer.status === 'declined') return json({ error: 'Already declined' }, 409);

      const envelope = await env.DB.prepare('SELECT * FROM envelopes WHERE id = ?').bind(signer.envelope_id).first();
      if (!envelope) return json({ error: 'Envelope not found' }, 404);
      if (envelope.expires_at && new Date(envelope.expires_at as string) < new Date()) return json({ error: 'Expired' }, 410);

      const body = await req.json<Record<string, string>>().catch(() => null);
      if (!body) return json({ error: 'Invalid body' }, 400);

      const ua = sanitize(req.headers.get('User-Agent'), 500);

      // Update field values
      const fields = await env.DB.prepare('SELECT * FROM fields WHERE envelope_id = ? AND (signer_id = ? OR signer_id IS NULL)').bind(envelope.id, signer.id).all();
      const fieldUpdates = [];
      let sigData = '';
      for (const f of fields.results) {
        const val = body[`field_${f.id}`];
        if (val) {
          fieldUpdates.push(env.DB.prepare('UPDATE fields SET value = ?, filled_at = datetime("now") WHERE id = ?').bind(sanitize(val, 100000), f.id));
          if (f.type === 'signature') sigData = val;
        }
      }

      const stmts = [
        ...fieldUpdates,
        env.DB.prepare('UPDATE signers SET status = "signed", signature_data = ?, signed_at = datetime("now"), signed_ip = ?, signed_ua = ? WHERE id = ?')
          .bind(sigData, ip, ua, signer.id),
        env.DB.prepare('UPDATE envelopes SET signed_count = signed_count + 1, updated_at = datetime("now") WHERE id = ?').bind(envelope.id),
        env.DB.prepare('INSERT INTO audit_trail (envelope_id, tenant_id, signer_id, action, ip, user_agent, details) VALUES (?, ?, ?, ?, ?, ?, ?)')
          .bind(envelope.id, envelope.tenant_id, signer.id, 'signed', ip, ua, JSON.stringify({ fields_filled: fieldUpdates.length })),
      ];
      await env.DB.batch(stmts);

      // Check if all signers done
      const remaining = await env.DB.prepare('SELECT COUNT(*) as c FROM signers WHERE envelope_id = ? AND role = "signer" AND status != "signed"').bind(envelope.id).first();
      if ((remaining?.c as number) === 0) {
        await env.DB.prepare('UPDATE envelopes SET status = "completed", completed_at = datetime("now"), updated_at = datetime("now") WHERE id = ?').bind(envelope.id).run();
        await env.DB.prepare('INSERT INTO audit_trail (envelope_id, tenant_id, action, details) VALUES (?, ?, ?, ?)').bind(envelope.id, envelope.tenant_id, 'completed', '{"all_signed":true}').run();

        // Notify owner (ctx.waitUntil to ensure delivery)
        ctx.waitUntil((async () => {
          try {
            const tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(envelope.tenant_id).first();
            if (tenant?.email) {
              await env.EMAIL_SENDER.fetch('https://email/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  to: tenant.email,
                  subject: `All signatures collected: ${envelope.title}`,
                  html: `<h2>Document Completed</h2><p>"${envelope.title}" has been signed by all parties.</p>`,
                }),
              });
            }
          } catch (_) { /* non-blocking */ }
        })());
      } else if (envelope.sequential) {
        // Send next signer in sequence (ctx.waitUntil to ensure delivery)
        ctx.waitUntil((async () => {
          try {
            const nextSigner = await env.DB.prepare('SELECT * FROM signers WHERE envelope_id = ? AND status = "pending" ORDER BY order_num LIMIT 1').bind(envelope.id).first();
            if (nextSigner) {
              await env.EMAIL_SENDER.fetch('https://email/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  to: nextSigner.email,
                  subject: `Signature requested: ${envelope.title}`,
                  html: `<h2>Your Signature Is Needed</h2><p>${envelope.message || 'Please review and sign this document.'}</p><p><a href="https://echo-signatures.bmcii1976.workers.dev/sign/${nextSigner.token}" style="display:inline-block;padding:14px 28px;background:${(await env.DB.prepare('SELECT brand_color FROM tenants WHERE id = ?').bind(envelope.tenant_id).first())?.brand_color || '#14b8a6'};color:#fff;border-radius:8px;text-decoration:none;font-weight:bold">Review & Sign</a></p>`,
                }),
              });
              await env.DB.prepare('UPDATE signers SET status = "sent" WHERE id = ?').bind(nextSigner.id).run();
            }
          } catch (_) { /* non-blocking */ }
        })());
      }

      return json({ signed: true, message: 'Document signed successfully. Thank you!' });
    }

    // ── Public: Decline (POST /decline/:token) ──
    if (m === 'POST' && p.startsWith('/decline/')) {
      const signerToken = p.split('/')[2];
      if (!(await rateLimit(env, `decline:${ip}`, 10, 3600))) return json({ error: 'Rate limited' }, 429);

      const signer = await env.DB.prepare('SELECT * FROM signers WHERE token = ?').bind(signerToken).first();
      if (!signer) return json({ error: 'Invalid token' }, 404);

      const body = await req.json<{ reason?: string }>().catch(() => ({}));

      await env.DB.batch([
        env.DB.prepare('UPDATE signers SET status = "declined", declined_at = datetime("now"), decline_reason = ? WHERE id = ?')
          .bind(sanitize((body as { reason?: string })?.reason, 1000), signer.id),
        env.DB.prepare('UPDATE envelopes SET status = "declined", updated_at = datetime("now") WHERE id = ?').bind(signer.envelope_id),
        env.DB.prepare('INSERT INTO audit_trail (envelope_id, tenant_id, signer_id, action, ip, details) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(signer.envelope_id, signer.tenant_id, signer.id, 'declined', ip, JSON.stringify({ reason: sanitize((body as { reason?: string })?.reason, 1000) })),
      ]);

      return json({ declined: true });
    }

    // ── Public: Audit Trail Certificate (GET /certificate/:slug) ──
    if (m === 'GET' && p.startsWith('/certificate/')) {
      const slug = p.split('/')[2];
      const envelope = await env.DB.prepare('SELECT * FROM envelopes WHERE slug = ? AND status = "completed"').bind(slug).first();
      if (!envelope) return json({ error: 'Not found or not completed' }, 404);

      const signers = await env.DB.prepare('SELECT name, email, role, status, signed_at, signed_ip FROM signers WHERE envelope_id = ? ORDER BY order_num').bind(envelope.id).all();
      const audit = await env.DB.prepare('SELECT action, ip, created_at, details FROM audit_trail WHERE envelope_id = ? ORDER BY created_at').bind(envelope.id).all();

      return json({
        certificate: {
          document: envelope.title,
          envelope_id: envelope.id,
          created: envelope.created_at,
          completed: envelope.completed_at,
          signers: signers.results,
          audit_trail: audit.results,
        },
      });
    }

    // ── Stripe Webhook (no auth — signature verified) ──
    if (m === 'POST' && p === '/webhooks/stripe') {
      if (!env.STRIPE_WEBHOOK_SECRET) return json({ error: 'Webhook not configured' }, 503);
      const body = await req.text();
      const sig = req.headers.get('Stripe-Signature') || '';
      if (!(await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET))) {
        slog('warn', 'Stripe webhook signature verification failed', { ip });
        return json({ error: 'Invalid signature' }, 401);
      }
      const event = JSON.parse(body);
      slog('info', 'Stripe webhook received', { type: event.type, id: event.id });

      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const tenantId = session.metadata?.tenant_id;
        const credits = parseInt(session.metadata?.credits || '0');
        const pack = session.metadata?.pack || 'custom';
        if (!tenantId || credits <= 0) return json({ error: 'Missing metadata' }, 400);

        await env.DB.batch([
          env.DB.prepare('UPDATE tenants SET envelope_credits = envelope_credits + ?, total_purchased = total_purchased + ? WHERE id = ?').bind(credits, credits, tenantId),
          env.DB.prepare('INSERT INTO credit_transactions (id, tenant_id, type, credits, pack, amount_cents, stripe_checkout_id, stripe_payment_intent, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(
            uid(), tenantId, 'purchase', credits, pack,
            session.amount_total || 0, session.id, session.payment_intent || null,
            `Purchased ${credits} envelope credits (${pack})`
          ),
        ]);
        slog('info', 'Credits added via Stripe', { tenant_id: tenantId, credits, pack });
        try {
          const tenant = await env.DB.prepare('SELECT email FROM tenants WHERE id = ?').bind(tenantId).first();
          if (tenant?.email) {
            await env.EMAIL_SENDER.fetch('https://email/send', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ to: tenant.email, subject: `${credits} envelope credits added`, html: `<h2>Credits Added!</h2><p>${credits} envelope credits have been added to your account (${pack} pack).</p>` }),
            });
          }
        } catch (_) { /* non-blocking */ }
      }
      if (event.type === 'checkout.session.expired') {
        slog('info', 'Stripe checkout expired', { session_id: event.data.object.id });
      }
      return json({ received: true });
    }

    // ── Public: Pricing Page ──
    if (m === 'GET' && p === '/public/pricing') {
      const accept = req.headers.get('Accept') || '';
      if (accept.includes('application/json')) {
        return json({ packs: CREDIT_PACKS, currency: 'usd' });
      }
      return new Response(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Echo Signatures — Pricing</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#0a0f1a;color:#e2e8f0;min-height:100vh;display:flex;justify-content:center;padding:40px 16px}
.wrap{max-width:900px;width:100%}h1{font-size:32px;font-weight:800;text-align:center;margin-bottom:8px}
.sub{text-align:center;color:#94a3b8;margin-bottom:40px;font-size:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.pack{background:#0c1220;border:1px solid #1e293b;border-radius:16px;padding:28px;text-align:center;transition:border-color .2s}
.pack:hover{border-color:#14b8a6}.pack h3{font-size:18px;margin-bottom:4px}
.price{font-size:36px;font-weight:800;color:#14b8a6;margin:12px 0}.unit{font-size:13px;color:#64748b}
.credits{font-size:14px;color:#94a3b8;margin:8px 0 20px}.btn{display:inline-block;width:100%;padding:14px;background:#14b8a6;color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:700;cursor:pointer;text-decoration:none}.btn:hover{opacity:.9}
.feat{margin-top:40px;text-align:center;color:#64748b;font-size:13px}
</style></head><body><div class="wrap">
<h1>E-Signature Credits</h1>
<p class="sub">Pay per envelope — no monthly commitment. Every credit = one envelope sent.</p>
<div class="grid">
${CREDIT_PACKS.map(p => `<div class="pack"><h3>${p.name}</h3><div class="price">${p.display}</div><div class="credits">${p.credits} envelopes</div><div class="unit">$${(p.price / p.credits / 100).toFixed(2)}/envelope</div><div style="margin-top:16px"><span class="btn">Buy Now</span></div></div>`).join('')}
</div>
<p class="feat">All plans include: Legally binding e-signatures &bull; Audit trail &bull; Email notifications &bull; Sequential signing &bull; Templates &bull; Bulk send &bull; CSV export</p>
</div></body></html>`, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // ═══════════════════════════════════════
    // AUTH REQUIRED BELOW
    // ═══════════════════════════════════════
    try {
    if (!authOk(req, env)) return json({ error: 'Unauthorized — X-Echo-API-Key or Bearer token required' }, 401);
    const tenantId = tid(req);

    // ── Tenants CRUD ──
    if (p === '/tenants' && m === 'POST') {
      const body = await req.json<Record<string, unknown>>().catch(() => null);
      if (!body?.name) return json({ error: 'name required' }, 400);
      const id = uid();
      await env.DB.prepare('INSERT INTO tenants (id, name, logo_url, brand_color, email, company, default_reminder_days, default_expiry_days) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(id, sanitize(body.name as string, 200), sanitize(body.logo_url as string, 500), body.brand_color || '#14b8a6',
          sanitize(body.email as string, 200), sanitize(body.company as string, 200),
          Number(body.default_reminder_days) || 3, Number(body.default_expiry_days) || 30).run();
      return json({ id }, 201);
    }
    if (p === '/tenants' && m === 'GET') {
      const row = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(tenantId).first();
      return row ? json(row) : json({ error: 'Not found' }, 404);
    }
    if (p === '/tenants' && m === 'PATCH') {
      const body = await req.json<Record<string, unknown>>().catch(() => ({}));
      const f: string[] = []; const v: unknown[] = [];
      for (const [k, val] of Object.entries(body as Record<string, unknown>)) {
        if (['name','logo_url','brand_color','email','company','default_reminder_days','default_expiry_days'].includes(k)) {
          f.push(`${k} = ?`); v.push(typeof val === 'string' ? sanitize(val, 500) : val);
        }
      }
      if (f.length === 0) return json({ error: 'No fields' }, 400);
      v.push(tenantId);
      await env.DB.prepare(`UPDATE tenants SET ${f.join(', ')} WHERE id = ?`).bind(...v).run();
      return json({ updated: true });
    }

    // ── Credits: Buy ──
    if (p === '/credits/buy' && m === 'POST') {
      if (!env.STRIPE_SECRET_KEY) return json({ error: 'Stripe not configured' }, 503);
      const body = await req.json<{ pack: string; success_url?: string; cancel_url?: string }>().catch(() => null);
      if (!body?.pack) return json({ error: 'pack required (starter|professional|business|enterprise)' }, 400);
      const pack = CREDIT_PACKS.find(p => p.id === body.pack);
      if (!pack) return json({ error: 'Invalid pack', valid: CREDIT_PACKS.map(p => p.id) }, 400);

      const baseUrl = body.success_url?.replace(/\/[^/]*$/, '') || 'https://echo-signatures.bmcii1976.workers.dev';
      const params = new URLSearchParams({
        'mode': 'payment',
        'success_url': body.success_url || `${baseUrl}/public/pricing?status=success`,
        'cancel_url': body.cancel_url || `${baseUrl}/public/pricing?status=cancelled`,
        'line_items[0][price_data][currency]': 'usd',
        'line_items[0][price_data][product_data][name]': `Echo Signatures — ${pack.name} Pack (${pack.credits} envelopes)`,
        'line_items[0][price_data][unit_amount]': String(pack.price),
        'line_items[0][quantity]': '1',
        'metadata[tenant_id]': tenantId,
        'metadata[credits]': String(pack.credits),
        'metadata[pack]': pack.id,
      });
      const resp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
      });
      const session = await resp.json() as Record<string, unknown>;
      if (!resp.ok) { slog('error', 'Stripe checkout failed', { status: resp.status, error: session }); return json({ error: 'Stripe error', details: session }, 502); }
      slog('info', 'Stripe checkout created', { tenant_id: tenantId, pack: pack.id, session_id: session.id });
      return json({ checkout_url: session.url, session_id: session.id, pack: pack.id, credits: pack.credits, price: pack.display });
    }

    // ── Credits: Balance ──
    if (p === '/credits' && m === 'GET') {
      const tenant = await env.DB.prepare('SELECT envelope_credits, total_purchased, plan_tier FROM tenants WHERE id = ?').bind(tenantId).first();
      if (!tenant) return json({ error: 'Tenant not found' }, 404);
      return json({ credits: tenant.envelope_credits, total_purchased: tenant.total_purchased, plan: tenant.plan_tier, packs: CREDIT_PACKS });
    }

    // ── Credits: Transaction History ──
    if (p === '/credits/transactions' && m === 'GET') {
      const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 200);
      const rows = await env.DB.prepare('SELECT * FROM credit_transactions WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?').bind(tenantId, limit).all();
      return json({ transactions: rows.results });
    }

    // ── Templates CRUD ──
    if (p === '/templates' && m === 'GET') {
      const rows = await env.DB.prepare('SELECT * FROM templates WHERE tenant_id = ? AND is_active = 1 ORDER BY created_at DESC').bind(tenantId).all();
      return json({ templates: rows.results });
    }
    if (p === '/templates' && m === 'POST') {
      const body = await req.json<Record<string, unknown>>().catch(() => null);
      if (!body?.name) return json({ error: 'name required' }, 400);
      const id = uid();
      await env.DB.prepare('INSERT INTO templates (id, tenant_id, name, description, fields, signers_config, message, redirect_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(id, tenantId, sanitize(body.name as string, 200), sanitize(body.description as string, 1000),
          JSON.stringify(body.fields || []), JSON.stringify(body.signers_config || []),
          sanitize(body.message as string, 2000), sanitize(body.redirect_url as string, 500)).run();
      return json({ id }, 201);
    }

    // ── Envelopes CRUD ──
    if (p === '/envelopes' && m === 'GET') {
      const status = url.searchParams.get('status');
      let q = 'SELECT * FROM envelopes WHERE tenant_id = ?';
      const binds: unknown[] = [tenantId];
      if (status) { q += ' AND status = ?'; binds.push(status); }
      q += ' ORDER BY created_at DESC LIMIT 100';
      const rows = await env.DB.prepare(q).bind(...binds).all();
      return json({ envelopes: rows.results });
    }
    if (p === '/envelopes' && m === 'POST') {
      const body = await req.json<Record<string, unknown>>().catch(() => null);
      if (!body?.title) return json({ error: 'title required' }, 400);
      const id = uid();
      const slug = slug8();
      const tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(tenantId).first();
      const expiryDays = Number(body.expiry_days) || (tenant?.default_expiry_days as number) || 30;
      const expiresAt = new Date(Date.now() + expiryDays * 86400000).toISOString();

      // If from template, clone fields/signers
      let templateFields: unknown[] = [];
      if (body.template_id) {
        const tmpl = await env.DB.prepare('SELECT * FROM templates WHERE id = ? AND tenant_id = ?').bind(body.template_id, tenantId).first();
        if (tmpl) {
          templateFields = JSON.parse((tmpl.fields as string) || '[]');
          await env.DB.prepare('UPDATE templates SET use_count = use_count + 1 WHERE id = ?').bind(body.template_id).run();
        }
      }

      await env.DB.prepare(
        'INSERT INTO envelopes (id, tenant_id, template_id, title, slug, message, sequential, redirect_url, expires_at, reminder_days) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(id, tenantId, body.template_id || null, sanitize(body.title as string, 200), slug,
        sanitize(body.message as string, 2000), body.sequential ? 1 : 0,
        sanitize(body.redirect_url as string, 500), expiresAt,
        Number(body.reminder_days) || (tenant?.default_reminder_days as number) || 3).run();

      // Create signers
      const signers = (body.signers as Array<{ name: string; email: string; role?: string; order?: number }>) || [];
      for (let i = 0; i < signers.length; i++) {
        const s = signers[i];
        const sid = uid();
        const tok = token32();
        await env.DB.prepare(
          'INSERT INTO signers (id, envelope_id, tenant_id, name, email, role, order_num, token) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        ).bind(sid, id, tenantId, sanitize(s.name, 200), sanitize(s.email, 200), s.role || 'signer', s.order || (i + 1), tok).run();

        // Create fields for each signer
        const fieldDefs = (body.fields as Array<{ type: string; label?: string; required?: boolean }>) || templateFields;
        for (const fd of fieldDefs as Array<Record<string, unknown>>) {
          await env.DB.prepare(
            'INSERT INTO fields (id, envelope_id, signer_id, type, label, required) VALUES (?, ?, ?, ?, ?, ?)'
          ).bind(uid(), id, sid, fd.type || 'signature', sanitize(fd.label as string, 200), fd.required !== false ? 1 : 0).run();
        }
      }

      await env.DB.prepare('UPDATE envelopes SET total_signers = ? WHERE id = ?').bind(signers.length, id).run();

      // Upsert contacts
      for (const s of signers) {
        await env.DB.prepare(
          'INSERT INTO contacts (id, tenant_id, name, email, company, total_envelopes) VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(tenant_id, email) DO UPDATE SET total_envelopes = total_envelopes + 1, name = excluded.name'
        ).bind(uid(), tenantId, sanitize(s.name, 200), sanitize(s.email, 200), '').run();
      }

      return json({ id, slug, signing_urls: [] }, 201);
    }

    if (p.match(/^\/envelopes\/[^/]+$/) && m === 'GET') {
      const id = p.split('/')[2];
      const envelope = await env.DB.prepare('SELECT * FROM envelopes WHERE id = ? AND tenant_id = ?').bind(id, tenantId).first();
      if (!envelope) return json({ error: 'Envelope not found' }, 404);
      const signers = await env.DB.prepare('SELECT id, name, email, role, order_num, status, signed_at, opened_at, view_count FROM signers WHERE envelope_id = ? ORDER BY order_num').bind(id).all();
      const fields = await env.DB.prepare('SELECT * FROM fields WHERE envelope_id = ?').bind(id).all();
      return json({ ...envelope, signers: signers.results, fields: fields.results });
    }

    // ── Send Envelope ──
    if (p.match(/^\/envelopes\/[^/]+\/send$/) && m === 'POST') {
      const id = p.split('/')[2];
      const envelope = await env.DB.prepare('SELECT * FROM envelopes WHERE id = ? AND tenant_id = ?').bind(id, tenantId).first();
      if (!envelope) return json({ error: 'Envelope not found' }, 404);
      if (envelope.status !== 'draft') return json({ error: 'Already sent' }, 400);

      const tenant = await env.DB.prepare('SELECT * FROM tenants WHERE id = ?').bind(tenantId).first();

      // Credit check (skip for unlimited plan)
      if (tenant && (tenant.plan_tier as string || 'free') !== 'unlimited') {
        const credits = (tenant.envelope_credits as number) || 0;
        if (credits <= 0) return json({ error: 'No envelope credits remaining. Purchase more credits to send envelopes.', buy_url: '/credits/buy', packs: CREDIT_PACKS }, 402);
      }

      const signers = await env.DB.prepare('SELECT * FROM signers WHERE envelope_id = ? ORDER BY order_num').bind(id).all();
      if (signers.results.length === 0) return json({ error: 'No signers' }, 400);
      const brandColor = (tenant?.brand_color as string) || '#14b8a6';

      // Send to first signer (if sequential) or all (if parallel)
      const toSend = envelope.sequential ? [signers.results[0]] : signers.results;
      const signingUrls: { name: string; email: string; url: string }[] = [];

      for (const s of toSend) {
        if ((s as Record<string, unknown>).role === 'cc' || (s as Record<string, unknown>).role === 'viewer') continue;
        const sigUrl = `https://echo-signatures.bmcii1976.workers.dev/sign/${(s as Record<string, unknown>).token}`;
        signingUrls.push({ name: s.name as string, email: s.email as string, url: sigUrl });

        ctx.waitUntil((async () => {
          try {
            await env.EMAIL_SENDER.fetch('https://email/send', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                to: s.email,
                subject: `Signature requested: ${envelope.title}`,
                html: `<div style="font-family:system-ui;max-width:500px;margin:0 auto;padding:24px">
<h2 style="color:#e2e8f0">Your Signature Is Needed</h2>
<p style="color:#94a3b8">${envelope.message || 'Please review and sign this document.'}</p>
<p style="margin:24px 0"><a href="${sigUrl}" style="display:inline-block;padding:14px 28px;background:${brandColor};color:#fff;border-radius:8px;text-decoration:none;font-weight:bold">Review & Sign</a></p>
<p style="font-size:12px;color:#475569">Powered by Echo Signatures</p></div>`,
              }),
            });
          } catch (_) { /* non-blocking */ }
        })());

        await env.DB.prepare('UPDATE signers SET status = "sent" WHERE id = ?').bind((s as Record<string, unknown>).id).run();
      }

      // CC/viewer notification
      for (const s of signers.results) {
        if ((s as Record<string, unknown>).role === 'cc') {
          ctx.waitUntil((async () => {
            try {
              await env.EMAIL_SENDER.fetch('https://email/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ to: s.email, subject: `CC: ${envelope.title} sent for signing`, html: `<p>You are CC'd on "${envelope.title}". You will be notified when it's completed.</p>` }),
              });
            } catch (_) { /* non-blocking */ }
          })());
        }
      }

      const sendBatch = [
        env.DB.prepare('UPDATE envelopes SET status = "sent", updated_at = datetime("now") WHERE id = ?').bind(id),
        env.DB.prepare('INSERT INTO audit_trail (envelope_id, tenant_id, action, details) VALUES (?, ?, ?, ?)').bind(id, tenantId, 'sent', JSON.stringify({ signers_notified: toSend.length })),
      ];
      // Deduct credit (skip for unlimited)
      if (tenant && (tenant.plan_tier as string || 'free') !== 'unlimited') {
        sendBatch.push(
          env.DB.prepare('UPDATE tenants SET envelope_credits = MAX(0, envelope_credits - 1) WHERE id = ?').bind(tenantId),
          env.DB.prepare('INSERT INTO credit_transactions (id, tenant_id, type, credits, description) VALUES (?, ?, ?, ?, ?)').bind(uid(), tenantId, 'usage', -1, `Envelope sent: ${envelope.title}`),
        );
      }
      await env.DB.batch(sendBatch);

      return json({ sent: true, signing_urls: signingUrls, credits_remaining: tenant ? Math.max(0, ((tenant.envelope_credits as number) || 0) - 1) : null });
    }

    // ── Void Envelope ──
    if (p.match(/^\/envelopes\/[^/]+\/void$/) && m === 'POST') {
      const id = p.split('/')[2];
      const body = await req.json<{ reason?: string }>().catch(() => ({}));
      await env.DB.batch([
        env.DB.prepare('UPDATE envelopes SET status = "voided", voided_at = datetime("now"), void_reason = ?, updated_at = datetime("now") WHERE id = ? AND tenant_id = ?')
          .bind(sanitize((body as { reason?: string })?.reason, 1000), id, tenantId),
        env.DB.prepare('INSERT INTO audit_trail (envelope_id, tenant_id, action, details) VALUES (?, ?, ?, ?)').bind(id, tenantId, 'voided', JSON.stringify(body)),
      ]);
      return json({ voided: true });
    }

    // ── Remind Signers ──
    if (p.match(/^\/envelopes\/[^/]+\/remind$/) && m === 'POST') {
      const id = p.split('/')[2];
      const envelope = await env.DB.prepare('SELECT * FROM envelopes WHERE id = ? AND tenant_id = ?').bind(id, tenantId).first();
      if (!envelope) return json({ error: 'Envelope not found' }, 404);

      const pending = await env.DB.prepare('SELECT * FROM signers WHERE envelope_id = ? AND status IN ("sent","opened")').bind(id).all();
      let reminded = 0;
      for (const s of pending.results) {
        ctx.waitUntil((async () => {
          try {
            await env.EMAIL_SENDER.fetch('https://email/send', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                to: s.email,
                subject: `Reminder: Please sign "${envelope.title}"`,
                html: `<p>This is a friendly reminder that your signature is needed on "${envelope.title}".</p><p><a href="https://echo-signatures.bmcii1976.workers.dev/sign/${s.token}" style="display:inline-block;padding:14px 28px;background:#14b8a6;color:#fff;border-radius:8px;text-decoration:none;font-weight:bold">Review & Sign</a></p>`,
              }),
            });
          } catch (_) { /* non-blocking */ }
        })());
        await env.DB.prepare('UPDATE signers SET reminded_count = reminded_count + 1 WHERE id = ?').bind(s.id).run();
        reminded++;
      }

      return json({ reminded });
    }

    // ── Bulk Send ──
    if (p === '/envelopes/bulk' && m === 'POST') {
      const body = await req.json<{ template_id: string; recipients: Array<{ name: string; email: string }>; message?: string }>().catch(() => null);
      if (!body?.template_id || !body?.recipients?.length) return json({ error: 'template_id, recipients required' }, 400);
      if (body.recipients.length > 50) return json({ error: 'Max 50 per batch' }, 400);

      const tmpl = await env.DB.prepare('SELECT * FROM templates WHERE id = ? AND tenant_id = ?').bind(body.template_id, tenantId).first();
      if (!tmpl) return json({ error: 'Template not found' }, 404);

      const created: string[] = [];
      for (const r of body.recipients) {
        const id = uid();
        const slug = slug8();
        const tenant = await env.DB.prepare('SELECT default_expiry_days FROM tenants WHERE id = ?').bind(tenantId).first();
        const expiresAt = new Date(Date.now() + ((tenant?.default_expiry_days as number) || 30) * 86400000).toISOString();

        await env.DB.prepare(
          'INSERT INTO envelopes (id, tenant_id, template_id, title, slug, message, expires_at, total_signers) VALUES (?, ?, ?, ?, ?, ?, ?, 1)'
        ).bind(id, tenantId, body.template_id, sanitize(tmpl.name as string, 200), slug, sanitize(body.message || tmpl.message as string, 2000), expiresAt).run();

        const sid = uid();
        const tok = token32();
        await env.DB.prepare('INSERT INTO signers (id, envelope_id, tenant_id, name, email, role, order_num, token) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(sid, id, tenantId, sanitize(r.name, 200), sanitize(r.email, 200), 'signer', 1, tok).run();

        const fieldDefs = JSON.parse((tmpl.fields as string) || '[]');
        for (const fd of fieldDefs) {
          await env.DB.prepare('INSERT INTO fields (id, envelope_id, signer_id, type, label, required) VALUES (?, ?, ?, ?, ?, ?)')
            .bind(uid(), id, sid, fd.type || 'signature', sanitize(fd.label, 200), fd.required !== false ? 1 : 0).run();
        }

        created.push(id);
      }

      await env.DB.prepare('UPDATE templates SET use_count = use_count + ? WHERE id = ?').bind(body.recipients.length, body.template_id).run();
      return json({ created: created.length, envelope_ids: created }, 201);
    }

    // ── Contacts ──
    if (p === '/contacts' && m === 'GET') {
      const rows = await env.DB.prepare('SELECT * FROM contacts WHERE tenant_id = ? ORDER BY total_envelopes DESC LIMIT 100').bind(tenantId).all();
      return json({ contacts: rows.results });
    }

    // ── Audit Trail ──
    if (p.match(/^\/envelopes\/[^/]+\/audit$/) && m === 'GET') {
      const id = p.split('/')[2];
      const rows = await env.DB.prepare('SELECT a.*, s.name as signer_name FROM audit_trail a LEFT JOIN signers s ON a.signer_id = s.id WHERE a.envelope_id = ? AND a.tenant_id = ? ORDER BY a.created_at').bind(id, tenantId).all();
      return json({ audit: rows.results });
    }

    // ── Analytics ──
    if (p === '/analytics/overview' && m === 'GET') {
      const cacheKey = `analytics:${tenantId}:overview`;
      const cached = await env.CACHE.get(cacheKey, 'json');
      if (cached) return json(cached);

      const totals = await env.DB.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN status="completed" THEN 1 ELSE 0 END) as completed, SUM(CASE WHEN status="sent" OR status="in_progress" THEN 1 ELSE 0 END) as pending, SUM(CASE WHEN status="declined" THEN 1 ELSE 0 END) as declined, SUM(CASE WHEN status="expired" THEN 1 ELSE 0 END) as expired FROM envelopes WHERE tenant_id = ?').bind(tenantId).first();
      const sigStats = await env.DB.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN status="signed" THEN 1 ELSE 0 END) as signed FROM signers WHERE tenant_id = ?').bind(tenantId).first();

      const result = { envelopes: totals, signatures: sigStats };
      await env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 300 });
      return json(result);
    }

    if (p === '/analytics/trends' && m === 'GET') {
      const days = Number(url.searchParams.get('days')) || 30;
      const rows = await env.DB.prepare('SELECT * FROM analytics_daily WHERE tenant_id = ? AND date >= date("now", ? || " days") ORDER BY date DESC').bind(tenantId, `-${days}`).all();
      return json({ trends: rows.results });
    }

    // ── Export ──
    if (p === '/export' && m === 'GET') {
      const format = url.searchParams.get('format') || 'json';
      const rows = await env.DB.prepare('SELECT e.*, (SELECT GROUP_CONCAT(s.name || " <" || s.email || "> (" || s.status || ")", "; ") FROM signers s WHERE s.envelope_id = e.id) as signer_list FROM envelopes e WHERE e.tenant_id = ? ORDER BY e.created_at DESC').bind(tenantId).all();
      if (format === 'csv') {
        const data = rows.results;
        if (data.length === 0) return new Response('', { headers: { 'Content-Type': 'text/csv' } });
        const headers = Object.keys(data[0]);
        const csv = [headers.join(','), ...data.map(r => headers.map(h => `"${String((r as Record<string, unknown>)[h] ?? '').replace(/"/g, '""')}"`).join(','))].join('\n');
        return new Response(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=envelopes_export.csv' } });
      }
      return json({ envelopes: rows.results });
    }

    // ── Activity Log ──
    if (p === '/activity' && m === 'GET') {
      const rows = await env.DB.prepare('SELECT * FROM activity_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100').bind(tenantId).all();
      return json({ activity: rows.results });
    }

    // ── Admin: Stripe Migration ──
    if (p === '/admin/migrate-stripe' && m === 'POST') {
      const stmts = [
        env.DB.prepare(`ALTER TABLE tenants ADD COLUMN envelope_credits INTEGER DEFAULT 5`),
        env.DB.prepare(`ALTER TABLE tenants ADD COLUMN total_purchased INTEGER DEFAULT 0`),
        env.DB.prepare(`ALTER TABLE tenants ADD COLUMN stripe_customer_id TEXT`),
        env.DB.prepare(`ALTER TABLE tenants ADD COLUMN plan_tier TEXT DEFAULT 'free'`),
        env.DB.prepare(`CREATE TABLE IF NOT EXISTS credit_transactions (
          id TEXT PRIMARY KEY,
          tenant_id TEXT NOT NULL,
          type TEXT NOT NULL DEFAULT 'purchase',
          credits INTEGER NOT NULL,
          pack TEXT,
          amount_cents INTEGER DEFAULT 0,
          stripe_checkout_id TEXT,
          stripe_payment_intent TEXT,
          description TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        )`),
        env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_credit_tx_tenant ON credit_transactions(tenant_id, created_at)`),
      ];
      const results = [];
      for (const s of stmts) {
        try { await s.run(); results.push('OK'); }
        catch (e: any) { results.push(e.message?.includes('duplicate') || e.message?.includes('already exists') ? 'SKIP (exists)' : `ERR: ${e.message}`); }
      }
      slog('info', 'Stripe migration completed', { results });
      return json({ migrated: true, results });
    }

    return json({ error: 'Not found' }, 404);

    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      const stack = err instanceof Error ? err.stack : undefined;
      slog('error', 'Unhandled request error', { method: m, path: p, error: msg, stack });
      return json({ error: 'Internal server error', message: msg, path: p }, 500);
    }

    } catch (e: any) {
      if (e.message?.includes('JSON')) {
        return json({ error: 'Invalid JSON body' }, 400);
      }
      slog('error', 'Unhandled request error', { error: e.message, stack: e.stack });
      return json({ error: 'Internal server error' }, 500);
    }
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

    // Daily analytics
    const tenants = await env.DB.prepare('SELECT DISTINCT tenant_id FROM envelopes').all();
    for (const t of tenants.results) {
      const tid = t.tenant_id as string;
      const created = await env.DB.prepare('SELECT COUNT(*) as c FROM envelopes WHERE tenant_id = ? AND date(created_at) = ?').bind(tid, yesterday).first();
      const sent = await env.DB.prepare('SELECT COUNT(*) as c FROM envelopes WHERE tenant_id = ? AND date(updated_at) = ? AND status != "draft"').bind(tid, yesterday).first();
      const completed = await env.DB.prepare('SELECT COUNT(*) as c FROM envelopes WHERE tenant_id = ? AND date(completed_at) = ?').bind(tid, yesterday).first();
      const declined = await env.DB.prepare('SELECT COUNT(*) as c FROM envelopes WHERE tenant_id = ? AND status = "declined" AND date(updated_at) = ?').bind(tid, yesterday).first();
      const sigs = await env.DB.prepare('SELECT COUNT(*) as c FROM signers WHERE tenant_id = ? AND date(signed_at) = ?').bind(tid, yesterday).first();

      await env.DB.prepare(
        'INSERT OR REPLACE INTO analytics_daily (tenant_id, date, envelopes_created, envelopes_sent, envelopes_completed, envelopes_declined, signatures_collected) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(tid, yesterday, created?.c || 0, sent?.c || 0, completed?.c || 0, declined?.c || 0, sigs?.c || 0).run();
    }

    // Expire old envelopes
    await env.DB.prepare('UPDATE envelopes SET status = "expired" WHERE status IN ("sent","in_progress") AND expires_at < datetime("now")').run();

    // Auto-reminders
    const needReminder = await env.DB.prepare(
      'SELECT s.*, e.title, e.reminder_days FROM signers s JOIN envelopes e ON s.envelope_id = e.id WHERE s.status IN ("sent","opened") AND e.status IN ("sent","in_progress") AND (s.reminded_count = 0 AND julianday("now") - julianday(s.created_at) >= e.reminder_days OR s.reminded_count > 0 AND julianday("now") - julianday(COALESCE(s.created_at, s.created_at)) >= e.reminder_days) LIMIT 50'
    ).all();

    for (const s of needReminder.results) {
      ctx.waitUntil((async () => {
        try {
          await env.EMAIL_SENDER.fetch('https://email/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              to: s.email,
              subject: `Reminder: Please sign "${s.title}"`,
              html: `<p>This is a reminder that your signature is still needed on "${s.title}".</p><p><a href="https://echo-signatures.bmcii1976.workers.dev/sign/${s.token}" style="display:inline-block;padding:14px 28px;background:#14b8a6;color:#fff;border-radius:8px;text-decoration:none;font-weight:bold">Review & Sign</a></p>`,
            }),
          });
          await env.DB.prepare('UPDATE signers SET reminded_count = reminded_count + 1 WHERE id = ?').bind(s.id).run();
        } catch (_) { /* non-blocking */ }
      })());
    }
  },
};
