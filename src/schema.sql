-- Echo Signatures v1.0.0 Schema

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  logo_url TEXT,
  brand_color TEXT DEFAULT '#14b8a6',
  email TEXT,
  company TEXT,
  default_reminder_days INTEGER DEFAULT 3,
  default_expiry_days INTEGER DEFAULT 30,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS templates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  fields TEXT DEFAULT '[]',
  signers_config TEXT DEFAULT '[]',
  message TEXT,
  redirect_url TEXT,
  use_count INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS envelopes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  template_id TEXT,
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  message TEXT,
  status TEXT DEFAULT 'draft' CHECK(status IN ('draft','sent','in_progress','completed','declined','expired','voided')),
  sequential INTEGER DEFAULT 0,
  redirect_url TEXT,
  expires_at TEXT,
  completed_at TEXT,
  voided_at TEXT,
  void_reason TEXT,
  total_signers INTEGER DEFAULT 0,
  signed_count INTEGER DEFAULT 0,
  reminder_days INTEGER DEFAULT 3,
  last_reminder_at TEXT,
  metadata TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE TABLE IF NOT EXISTS signers (
  id TEXT PRIMARY KEY,
  envelope_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT DEFAULT 'signer' CHECK(role IN ('signer','approver','viewer','cc')),
  order_num INTEGER DEFAULT 1,
  token TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'pending' CHECK(status IN ('pending','sent','opened','signed','declined')),
  signature_data TEXT,
  signed_at TEXT,
  signed_ip TEXT,
  signed_ua TEXT,
  declined_at TEXT,
  decline_reason TEXT,
  opened_at TEXT,
  last_viewed_at TEXT,
  view_count INTEGER DEFAULT 0,
  reminded_count INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (envelope_id) REFERENCES envelopes(id)
);

CREATE TABLE IF NOT EXISTS fields (
  id TEXT PRIMARY KEY,
  envelope_id TEXT NOT NULL,
  signer_id TEXT,
  type TEXT DEFAULT 'signature' CHECK(type IN ('signature','initials','text','date','checkbox','dropdown','attachment')),
  label TEXT,
  required INTEGER DEFAULT 1,
  page INTEGER DEFAULT 1,
  x REAL DEFAULT 0,
  y REAL DEFAULT 0,
  width REAL DEFAULT 200,
  height REAL DEFAULT 60,
  value TEXT,
  options TEXT DEFAULT '[]',
  filled_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (envelope_id) REFERENCES envelopes(id)
);

CREATE TABLE IF NOT EXISTS audit_trail (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  envelope_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  signer_id TEXT,
  action TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  details TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (envelope_id) REFERENCES envelopes(id)
);

CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  company TEXT,
  total_envelopes INTEGER DEFAULT 0,
  last_signed_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(tenant_id, email)
);

CREATE TABLE IF NOT EXISTS analytics_daily (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  date TEXT NOT NULL,
  envelopes_created INTEGER DEFAULT 0,
  envelopes_sent INTEGER DEFAULT 0,
  envelopes_completed INTEGER DEFAULT 0,
  envelopes_declined INTEGER DEFAULT 0,
  signatures_collected INTEGER DEFAULT 0,
  avg_completion_hours REAL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(tenant_id, date)
);

CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  envelope_id TEXT,
  action TEXT NOT NULL,
  details TEXT DEFAULT '{}',
  actor TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_envelopes_tenant ON envelopes(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_envelopes_status ON envelopes(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_envelopes_slug ON envelopes(slug);
CREATE INDEX IF NOT EXISTS idx_signers_envelope ON signers(envelope_id, order_num);
CREATE INDEX IF NOT EXISTS idx_signers_token ON signers(token);
CREATE INDEX IF NOT EXISTS idx_signers_email ON signers(email);
CREATE INDEX IF NOT EXISTS idx_fields_envelope ON fields(envelope_id, page);
CREATE INDEX IF NOT EXISTS idx_audit_envelope ON audit_trail(envelope_id, created_at);
CREATE INDEX IF NOT EXISTS idx_contacts_tenant ON contacts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_analytics_tenant ON analytics_daily(tenant_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id, created_at DESC);
