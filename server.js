// SafeLoop – PostgreSQL (Neon-ready) server. Set DATABASE_URL. Node 18+.
const http = require("http"),
  fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const { Pool, types } = require("pg");
types.setTypeParser(20, (v) => Number(v)); // BIGINT -> JS number (timestamps)
const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL) {
  console.error(
    "DATABASE_URL is not set. Add your Neon connection string as an environment variable.",
  );
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
});
pool.on("error", (e) => console.error("DB pool error:", e.message));
const toPg = (sql) => {
  let i = 0;
  return sql.replace(/\?/g, () => "$" + ++i);
}; // write SQL with ?, run as $1,$2…
const q = async (sql, ...a) => (await pool.query(toPg(sql), a)).rows;
const one = async (sql, ...a) => (await q(sql, ...a))[0];
const run = (sql, ...a) => pool.query(toPg(sql), a);
const ins = async (sql, ...a) => (await q(sql + " RETURNING id", ...a))[0].id;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pw TEXT NOT NULL, created BIGINT);
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires BIGINT);
CREATE TABLE IF NOT EXISTS contacts(id SERIAL PRIMARY KEY, sharer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  guardian_email TEXT NOT NULL, guardian_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending', level TEXT NOT NULL DEFAULT 'status', paused INTEGER NOT NULL DEFAULT 0,
  UNIQUE(sharer_id, guardian_email));
CREATE TABLE IF NOT EXISTS statuses(id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, label TEXT NOT NULL, at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS location(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, sharing INTEGER NOT NULL DEFAULT 0, lat DOUBLE PRECISION, lng DOUBLE PRECISION, acc DOUBLE PRECISION, at BIGINT);
CREATE TABLE IF NOT EXISTS alerts(id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, state TEXT NOT NULL DEFAULT 'active', lat DOUBLE PRECISION, lng DOUBLE PRECISION, acc DOUBLE PRECISION, loc_at BIGINT, at BIGINT, ack_by INTEGER);
CREATE TABLE IF NOT EXISTS notifications(id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT, title TEXT, body TEXT, ref INTEGER, at BIGINT, read INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_status ON statuses(user_id, at DESC);
CREATE INDEX IF NOT EXISTS ix_notif ON notifications(user_id, read, at DESC);
CREATE INDEX IF NOT EXISTS ix_contacts_g ON contacts(guardian_id);
`;
const LEVELS = ["status", "journey", "location"];
const now = () => Date.now(),
  sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const hashPw = (pw) => {
  const s = crypto.randomBytes(16);
  return s.toString("hex") + ":" + crypto.scryptSync(pw, s, 64).toString("hex");
};
const checkPw = (pw, st) => {
  const [s, h] = st.split(":");
  const x = crypto.scryptSync(pw, Buffer.from(s, "hex"), 64);
  return crypto.timingSafeEqual(x, Buffer.from(h, "hex"));
};

// ── realtime (SSE, single instance) ──
const streams = new Map();
function push(userId, ev) {
  for (const r of streams.get(userId) || [])
    r.write(`data: ${JSON.stringify(ev)}\n\n`);
}
async function notify(userId, type, title, body, ref) {
  await run(
    "INSERT INTO notifications(user_id,type,title,body,ref,at) VALUES(?,?,?,?,?,?)",
    userId,
    type,
    title,
    body,
    ref || null,
    now(),
  );
  push(userId, { type });
}
setInterval(() => {
  for (const set of streams.values())
    for (const r of set) r.write(": ping\n\n");
}, 25000); // keep proxies from closing idle streams

// ── authorization: the single gate for viewing someone else's data ──
async function canView(viewerId, subjectId, scope) {
  if (viewerId === subjectId) return true;
  const c = await one(
    `SELECT level,paused FROM contacts WHERE sharer_id=? AND guardian_id=? AND status='accepted'`,
    subjectId,
    viewerId,
  );
  if (!c || c.paused) return false;
  return LEVELS.indexOf(c.level) >= LEVELS.indexOf(scope);
}
async function guardiansOf(uid, minLevel = "status", ignorePause = false) {
  const rows = await q(
    `SELECT guardian_id,level,paused FROM contacts WHERE sharer_id=? AND status='accepted' AND guardian_id IS NOT NULL`,
    uid,
  );
  return rows
    .filter(
      (c) =>
        (ignorePause || !c.paused) &&
        LEVELS.indexOf(c.level) >= LEVELS.indexOf(minLevel),
    )
    .map((c) => c.guardian_id);
}

// ── http helpers ──
const hits = new Map();
const limited = (ip) => {
  const t = now(),
    a = (hits.get(ip) || []).filter((x) => t - x < 60000);
  a.push(t);
  hits.set(ip, a);
  return a.length > 20;
};
const clientIp = (req) =>
  (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
  req.socket.remoteAddress; // behind Render's proxy
const send = (res, code, obj, headers = {}) => {
  res.writeHead(code, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(obj));
};
const err = (res, code, msg) => send(res, code, { ok: false, error: msg });
const ok = (res, data = {}) => send(res, 200, { ok: true, ...data });
const body = (req) =>
  new Promise((resolve, reject) => {
    let d = "";
    req.on("data", (c) => {
      d += c;
      if (d.length > 1e5) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(d ? JSON.parse(d) : {});
      } catch {
        reject(new Error("bad json"));
      }
    });
  });
const cookie = (req) =>
  Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((s) => s.trim().split("="))
      .filter((x) => x[0]),
  );
async function sessionUser(req) {
  const t = cookie(req).sl;
  if (!t) return null;
  const s = await one(
    "SELECT user_id,expires FROM sessions WHERE hash=?",
    sha(t),
  );
  if (!s || s.expires < now()) return null;
  return one("SELECT id,email,name FROM users WHERE id=?", s.user_id);
}
async function startSession(userId) {
  const t = crypto.randomBytes(32).toString("hex");
  await run(
    "INSERT INTO sessions(hash,user_id,expires) VALUES(?,?,?)",
    sha(t),
    userId,
    now() + 7 * 864e5,
  );
  return `sl=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 86400}${process.env.NODE_ENV === "production" ? "; Secure" : ""}`;
}
const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const num = (v) => (typeof v === "number" && isFinite(v) ? v : null);
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// ── routes ──
async function api(req, res, url) {
  const m = req.method,
    p = url.pathname,
    ip = clientIp(req);
  if (
    m !== "GET" &&
    !(req.headers["content-type"] || "").includes("application/json")
  )
    return err(res, 415, "JSON required"); // blocks cross-site form posts
  const b = m === "GET" ? {} : await body(req);

  if (p === "/api/auth/register" && m === "POST") {
    if (limited(ip)) return err(res, 429, "Too many attempts");
    const email = str(b.email, 200).toLowerCase(),
      name = str(b.name, 80),
      pw = str(b.password, 200);
    if (!EMAIL.test(email) || !name || pw.length < 8)
      return err(
        res,
        400,
        "Valid email, name and 8+ character password required",
      );
    let id;
    try {
      id = await ins(
        "INSERT INTO users(email,name,pw,created) VALUES(?,?,?,?)",
        email,
        name,
        hashPw(pw),
        now(),
      );
    } catch (e) {
      if (e.code === "23505") return err(res, 409, "Email already registered");
      throw e;
    }
    await run("INSERT INTO location(user_id) VALUES(?)", id);
    await run(
      "UPDATE contacts SET guardian_id=? WHERE guardian_email=? AND guardian_id IS NULL",
      id,
      email,
    );
    return send(
      res,
      200,
      { ok: true },
      { "Set-Cookie": await startSession(id) },
    );
  }
  if (p === "/api/auth/login" && m === "POST") {
    if (limited(ip)) return err(res, 429, "Too many attempts");
    const u = await one(
      "SELECT * FROM users WHERE email=?",
      str(b.email, 200).toLowerCase(),
    );
    if (!u || !checkPw(str(b.password, 200), u.pw))
      return err(res, 401, "Wrong email or password");
    return send(
      res,
      200,
      { ok: true },
      { "Set-Cookie": await startSession(u.id) },
    );
  }
  const me = await sessionUser(req);
  if (p === "/api/auth/logout" && m === "POST") {
    const t = cookie(req).sl;
    if (t) await run("DELETE FROM sessions WHERE hash=?", sha(t));
    return send(
      res,
      200,
      { ok: true },
      { "Set-Cookie": "sl=; Max-Age=0; Path=/" },
    );
  }
  if (!me) return err(res, 401, "Sign in required");

  if (p === "/api/me")
    return ok(res, {
      user: me,
      sharing: !!(
        await one("SELECT sharing FROM location WHERE user_id=?", me.id)
      )?.sharing,
    });
  if (p === "/api/stream") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.write("retry: 3000\n\n");
    if (!streams.has(me.id)) streams.set(me.id, new Set());
    streams.get(me.id).add(res);
    req.on("close", () => streams.get(me.id)?.delete(res));
    return;
  }

  // contacts
  if (p === "/api/contacts" && m === "GET") {
    const mine = await q(
      `SELECT c.id,c.guardian_email email,c.status,c.level,c.paused,u.name FROM contacts c LEFT JOIN users u ON u.id=c.guardian_id WHERE c.sharer_id=?`,
      me.id,
    );
    const sharingWithMe = await q(
      `SELECT c.id,c.sharer_id "userId",c.status,c.level,c.paused,u.name FROM contacts c JOIN users u ON u.id=c.sharer_id WHERE c.guardian_id=? OR c.guardian_email=?`,
      me.id,
      me.email,
    );
    return ok(res, { mine, sharingWithMe });
  }
  if (p === "/api/contacts/invite" && m === "POST") {
    const email = str(b.email, 200).toLowerCase(),
      level = LEVELS.includes(b.level) ? b.level : "status";
    if (!EMAIL.test(email) || email === me.email)
      return err(res, 400, "Enter a different valid email");
    const g = await one("SELECT id FROM users WHERE email=?", email);
    let cid;
    try {
      cid = await ins(
        "INSERT INTO contacts(sharer_id,guardian_email,guardian_id,level) VALUES(?,?,?,?)",
        me.id,
        email,
        g?.id ?? null,
        level,
      );
    } catch (e) {
      if (e.code === "23505") return err(res, 409, "Already invited");
      throw e;
    }
    if (g)
      await notify(
        g.id,
        "contact_request",
        "New trusted-contact request",
        `${me.name} wants to share updates with you`,
        cid,
      );
    return ok(res);
  }
  let r;
  if ((r = p.match(/^\/api\/contacts\/(\d+)\/accept$/)) && m === "POST") {
    const c = await one(
      `SELECT * FROM contacts WHERE id=? AND (guardian_id=? OR guardian_email=?)`,
      +r[1],
      me.id,
      me.email,
    );
    if (!c) return err(res, 404, "Not found");
    await run(
      `UPDATE contacts SET status='accepted', guardian_id=? WHERE id=?`,
      me.id,
      c.id,
    );
    await notify(
      c.sharer_id,
      "contact_accepted",
      "Contact accepted",
      `${me.name} accepted your invitation`,
    );
    return ok(res);
  }
  if ((r = p.match(/^\/api\/contacts\/(\d+)$/))) {
    const c = await one(
      `SELECT * FROM contacts WHERE id=? AND (sharer_id=? OR guardian_id=?)`,
      +r[1],
      me.id,
      me.id,
    );
    if (!c) return err(res, 404, "Not found");
    if (m === "DELETE") {
      await run("DELETE FROM contacts WHERE id=?", c.id);
      push(c.sharer_id, { type: "refresh" });
      if (c.guardian_id) push(c.guardian_id, { type: "refresh" });
      return ok(res);
    }
    if (m === "PATCH") {
      // only the sharer controls what is shared
      if (c.sharer_id !== me.id)
        return err(res, 403, "Only the person sharing can change permissions");
      if (LEVELS.includes(b.level))
        await run("UPDATE contacts SET level=? WHERE id=?", b.level, c.id);
      if (typeof b.paused === "boolean")
        await run(
          "UPDATE contacts SET paused=? WHERE id=?",
          b.paused ? 1 : 0,
          c.id,
        );
      if (c.guardian_id) push(c.guardian_id, { type: "refresh" });
      return ok(res);
    }
  }

  // status
  if (p === "/api/status" && m === "POST") {
    const label = str(b.label, 280);
    if (!label) return err(res, 400, "Status text required");
    const id = await ins(
      "INSERT INTO statuses(user_id,label,at) VALUES(?,?,?)",
      me.id,
      label,
      now(),
    );
    for (const g of await guardiansOf(me.id))
      await notify(
        g,
        "status",
        `${me.name}: ${label}`,
        new Date().toLocaleTimeString(),
        id,
      );
    return ok(res, { id });
  }
  if (p === "/api/feed" && m === "GET") {
    const ids = [
      me.id,
      ...(
        await q(
          `SELECT sharer_id FROM contacts WHERE guardian_id=? AND status='accepted' AND paused=0`,
          me.id,
        )
      ).map((x) => x.sharer_id),
    ];
    const rows = await q(
      `SELECT s.id,s.label,s.at,u.name,u.id "userId" FROM statuses s JOIN users u ON u.id=s.user_id WHERE s.user_id IN (${ids.map(() => "?").join(",")}) ORDER BY s.at DESC LIMIT 30`,
      ...ids,
    );
    return ok(res, { items: rows });
  }

  // location – only the latest point is kept (data minimisation)
  if (p === "/api/location/update" && m === "POST") {
    const lat = num(b.lat),
      lng = num(b.lng);
    if (
      lat === null ||
      lng === null ||
      Math.abs(lat) > 90 ||
      Math.abs(lng) > 180
    )
      return err(res, 400, "Invalid coordinates");
    const was = (
      await one("SELECT sharing FROM location WHERE user_id=?", me.id)
    )?.sharing;
    await run(
      "UPDATE location SET sharing=1,lat=?,lng=?,acc=?,at=? WHERE user_id=?",
      lat,
      lng,
      num(b.acc),
      now(),
      me.id,
    );
    const gs = await guardiansOf(me.id, "location");
    if (!was)
      for (const g of gs)
        await notify(
          g,
          "location_started",
          "Location sharing started",
          `${me.name} is sharing live location`,
        );
    for (const g of gs) push(g, { type: "location", userId: me.id });
    return ok(res);
  }
  if (p === "/api/location/stop" && m === "POST") {
    await run(
      "UPDATE location SET sharing=0,lat=NULL,lng=NULL,acc=NULL WHERE user_id=?",
      me.id,
    );
    for (const g of await guardiansOf(me.id, "location"))
      await notify(
        g,
        "location_stopped",
        "Location sharing stopped",
        `${me.name} stopped sharing`,
      );
    return ok(res);
  }
  if ((r = p.match(/^\/api\/location\/current\/(\d+)$/)) && m === "GET") {
    const uid = +r[1];
    if (!(await canView(me.id, uid, "location")))
      return err(res, 403, "Not authorised");
    if (uid !== me.id)
      await run(
        "INSERT INTO notifications(user_id,type,title,body,at,read) VALUES(?,?,?,?,?,1)",
        uid,
        "audit",
        "Location viewed",
        `${me.name} viewed your location`,
        now(),
      );
    const l = await one(
      "SELECT sharing,lat,lng,acc,at FROM location WHERE user_id=?",
      uid,
    );
    return ok(res, { location: l && l.sharing ? l : null });
  }

  // emergency
  if (p === "/api/emergency" && m === "POST") {
    const l =
      (await one(
        "SELECT lat,lng,acc,at FROM location WHERE user_id=?",
        me.id,
      )) || {};
    const id = await ins(
      "INSERT INTO alerts(user_id,lat,lng,acc,loc_at,at) VALUES(?,?,?,?,?,?)",
      me.id,
      l.lat ?? null,
      l.lng ?? null,
      l.acc ?? null,
      l.at ?? null,
      now(),
    );
    for (const g of await guardiansOf(me.id, "status", true))
      await notify(
        g,
        "emergency",
        `EMERGENCY from ${me.name}`,
        l.lat != null
          ? `Last location ${l.lat.toFixed(4)}, ${l.lng.toFixed(4)}`
          : "No location available",
        id,
      );
    return ok(res, { id });
  }
  if (
    (r = p.match(/^\/api\/emergency\/(\d+)\/(acknowledge|resolve|cancel)$/)) &&
    m === "POST"
  ) {
    const a = await one("SELECT * FROM alerts WHERE id=?", +r[1]);
    if (!a) return err(res, 404, "Not found");
    const gs = await guardiansOf(a.user_id, "status", true),
      owner = a.user_id === me.id,
      guardian = gs.includes(me.id);
    if (r[2] === "cancel" && owner)
      await run(`UPDATE alerts SET state='cancelled' WHERE id=?`, a.id);
    else if (r[2] === "acknowledge" && guardian)
      await run(
        `UPDATE alerts SET state='acknowledged', ack_by=? WHERE id=?`,
        me.id,
        a.id,
      );
    else if (r[2] === "resolve" && (owner || guardian))
      await run(`UPDATE alerts SET state='resolved' WHERE id=?`, a.id);
    else return err(res, 403, "Not authorised");
    for (const u of [a.user_id, ...gs])
      if (u !== me.id)
        await notify(
          u,
          "emergency_update",
          `Emergency ${r[2]}`,
          `${me.name}: ${r[2]}`,
          a.id,
        );
    return ok(res);
  }
  if (p === "/api/emergency/active" && m === "GET") {
    const mine = await q(
      `SELECT * FROM alerts WHERE user_id=? AND state='active'`,
      me.id,
    );
    const others = await q(
      `SELECT a.*,u.name FROM alerts a JOIN users u ON u.id=a.user_id JOIN contacts c ON c.sharer_id=a.user_id WHERE c.guardian_id=? AND c.status='accepted' AND a.state IN ('active','acknowledged')`,
      me.id,
    );
    return ok(res, { mine, others });
  }

  // notifications
  if (p === "/api/notifications" && m === "GET") {
    const items = await q(
      `SELECT * FROM notifications WHERE user_id=? AND type!='audit' ORDER BY at DESC LIMIT 50`,
      me.id,
    );
    return ok(res, { items, unread: items.filter((i) => !i.read).length });
  }
  if (p === "/api/notifications/read" && m === "POST") {
    await run("UPDATE notifications SET read=1 WHERE user_id=?", me.id);
    return ok(res);
  }

  return err(res, 404, "Unknown endpoint");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    if (url.pathname.startsWith("/api/")) return await api(req, res, url);
    const f = path.join(
      __dirname,
      "public",
      url.pathname === "/"
        ? "index.html"
        : path.normalize(url.pathname).replace(/^(\.\.[\/\\])+/, ""),
    );
    if (!f.startsWith(path.join(__dirname, "public")) || !fs.existsSync(f)) {
      res.writeHead(404);
      return res.end("Not found");
    }
    res.writeHead(200, {
      "Content-Type": f.endsWith(".html") ? "text/html" : "text/plain",
      "X-Content-Type-Options": "nosniff",
    });
    fs.createReadStream(f).pipe(res);
  } catch (e) {
    console.error(e);
    if (!res.headersSent)
      err(res, 500, e.message === "bad json" ? "Invalid JSON" : "Server error");
  }
});
(async () => {
  try {
    await pool.query(SCHEMA);
    await pool.query("DELETE FROM sessions WHERE expires<$1", [now()]);
  } catch (e) {
    console.error("Could not connect to the database:", e.message);
    process.exit(1);
  }
  server.listen(PORT, () =>
    console.log(`SafeLoop running on http://localhost:${PORT}`),
  );
})();
