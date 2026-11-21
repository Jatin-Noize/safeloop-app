// SafeLoop – working server. Zero dependencies: Node 22+ (built-in node:sqlite, http, crypto).
const http = require("http"),
  fs = require("fs"),
  path = require("path"),
  crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");
const PORT = process.env.PORT || 3000;
const db = new DatabaseSync(
  process.env.DB_FILE || path.join(__dirname, "safeloop.db"),
);
db.exec(`
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pw TEXT NOT NULL, created INTEGER);
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER);
CREATE TABLE IF NOT EXISTS contacts(id INTEGER PRIMARY KEY, sharer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  guardian_email TEXT NOT NULL, guardian_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'pending', level TEXT NOT NULL DEFAULT 'status', paused INTEGER NOT NULL DEFAULT 0,
  UNIQUE(sharer_id, guardian_email));
CREATE TABLE IF NOT EXISTS statuses(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, label TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS location(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, sharing INTEGER NOT NULL DEFAULT 0, lat REAL, lng REAL, acc REAL, at INTEGER);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, state TEXT NOT NULL DEFAULT 'active', lat REAL, lng REAL, acc REAL, loc_at INTEGER, at INTEGER, ack_by INTEGER);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT, title TEXT, body TEXT, ref INTEGER, at INTEGER, read INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_status ON statuses(user_id, at DESC);
CREATE INDEX IF NOT EXISTS ix_notif ON notifications(user_id, read, at DESC);
`);
const q = (sql, ...a) => db.prepare(sql).all(...a),
  one = (sql, ...a) => db.prepare(sql).get(...a),
  run = (sql, ...a) => db.prepare(sql).run(...a);
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

// ── realtime (SSE) ──
const streams = new Map();
function notify(userId, type, title, body, ref) {
  run(
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
function push(userId, ev) {
  for (const r of streams.get(userId) || [])
    r.write(`data: ${JSON.stringify(ev)}\n\n`);
}

// ── authorization: the single gate for viewing someone else's data ──
function canView(viewerId, subjectId, scope) {
  if (viewerId === subjectId) return true;
  const c = one(
    `SELECT level,paused FROM contacts WHERE sharer_id=? AND guardian_id=? AND status='accepted'`,
    subjectId,
    viewerId,
  );
  if (!c || c.paused) return false;
  return LEVELS.indexOf(c.level) >= LEVELS.indexOf(scope);
}
const guardiansOf = (uid, minLevel = "status", ignorePause = false) =>
  q(
    `SELECT guardian_id,level,paused FROM contacts WHERE sharer_id=? AND status='accepted' AND guardian_id IS NOT NULL`,
    uid,
  )
    .filter(
      (c) =>
        (ignorePause || !c.paused) &&
        LEVELS.indexOf(c.level) >= LEVELS.indexOf(minLevel),
    )
    .map((c) => c.guardian_id);

// ── http helpers ──
const hits = new Map();
const limited = (ip) => {
  const t = now(),
    a = (hits.get(ip) || []).filter((x) => t - x < 60000);
  a.push(t);
  hits.set(ip, a);
  return a.length > 20;
};
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
function sessionUser(req) {
  const t = cookie(req).sl;
  if (!t) return null;
  const s = one("SELECT user_id,expires FROM sessions WHERE hash=?", sha(t));
  if (!s || s.expires < now()) return null;
  return one("SELECT id,email,name FROM users WHERE id=?", s.user_id);
}
function startSession(res, userId) {
  const t = crypto.randomBytes(32).toString("hex");
  run(
    "INSERT INTO sessions(hash,user_id,expires) VALUES(?,?,?)",
    sha(t),
    userId,
    now() + 7 * 864e5,
  );
  return `sl=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 86400}`;
}
const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const num = (v) => (typeof v === "number" && isFinite(v) ? v : null);

// ── routes ──
async function api(req, res, url) {
  const m = req.method,
    p = url.pathname,
    ip = req.socket.remoteAddress;
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
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !name || pw.length < 8)
      return err(
        res,
        400,
        "Valid email, name and 8+ character password required",
      );
    if (one("SELECT 1 x FROM users WHERE email=?", email))
      return err(res, 409, "Email already registered");
    const id = Number(
      run(
        "INSERT INTO users(email,name,pw,created) VALUES(?,?,?,?)",
        email,
        name,
        hashPw(pw),
        now(),
      ).lastInsertRowid,
    );
    run("INSERT INTO location(user_id) VALUES(?)", id);
    run(
      "UPDATE contacts SET guardian_id=? WHERE guardian_email=? AND guardian_id IS NULL",
      id,
      email,
    );
    return send(
      res,
      200,
      { ok: true },
      { "Set-Cookie": startSession(res, id) },
    );
  }
  if (p === "/api/auth/login" && m === "POST") {
    if (limited(ip)) return err(res, 429, "Too many attempts");
    const u = one(
      "SELECT * FROM users WHERE email=?",
      str(b.email, 200).toLowerCase(),
    );
    if (!u || !checkPw(str(b.password, 200), u.pw))
      return err(res, 401, "Wrong email or password");
    return send(
      res,
      200,
      { ok: true },
      { "Set-Cookie": startSession(res, u.id) },
    );
  }
  const me = sessionUser(req);
  if (p === "/api/auth/logout" && m === "POST") {
    const t = cookie(req).sl;
    if (t) run("DELETE FROM sessions WHERE hash=?", sha(t));
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
      sharing: !!one("SELECT sharing FROM location WHERE user_id=?", me.id)
        .sharing,
    });
  if (p === "/api/stream") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    res.write("retry: 3000\n\n");
    if (!streams.has(me.id)) streams.set(me.id, new Set());
    streams.get(me.id).add(res);
    req.on("close", () => streams.get(me.id)?.delete(res));
    return;
  }

  // contacts
  if (p === "/api/contacts" && m === "GET") {
    const mine = q(
      `SELECT c.id,c.guardian_email email,c.status,c.level,c.paused,u.name FROM contacts c LEFT JOIN users u ON u.id=c.guardian_id WHERE c.sharer_id=?`,
      me.id,
    );
    const sharingWithMe = q(
      `SELECT c.id,c.sharer_id userId,c.status,c.level,c.paused,u.name FROM contacts c JOIN users u ON u.id=c.sharer_id WHERE c.guardian_id=? OR c.guardian_email=?`,
      me.id,
      me.email,
    );
    return ok(res, { mine, sharingWithMe });
  }
  if (p === "/api/contacts/invite" && m === "POST") {
    const email = str(b.email, 200).toLowerCase(),
      level = LEVELS.includes(b.level) ? b.level : "status";
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email === me.email)
      return err(res, 400, "Enter a different valid email");
    const g = one("SELECT id FROM users WHERE email=?", email);
    try {
      const r = run(
        "INSERT INTO contacts(sharer_id,guardian_email,guardian_id,level) VALUES(?,?,?,?)",
        me.id,
        email,
        g?.id ?? null,
        level,
      );
      if (g)
        notify(
          g.id,
          "contact_request",
          "New trusted-contact request",
          `${me.name} wants to share updates with you`,
          Number(r.lastInsertRowid),
        );
    } catch {
      return err(res, 409, "Already invited");
    }
    return ok(res);
  }
  let r;
  if ((r = p.match(/^\/api\/contacts\/(\d+)\/accept$/)) && m === "POST") {
    const c = one(
      `SELECT * FROM contacts WHERE id=? AND (guardian_id=? OR guardian_email=?)`,
      +r[1],
      me.id,
      me.email,
    );
    if (!c) return err(res, 404, "Not found");
    run(
      `UPDATE contacts SET status='accepted', guardian_id=? WHERE id=?`,
      me.id,
      c.id,
    );
    notify(
      c.sharer_id,
      "contact_accepted",
      "Contact accepted",
      `${me.name} accepted your invitation`,
    );
    return ok(res);
  }
  if ((r = p.match(/^\/api\/contacts\/(\d+)$/))) {
    const c = one(
      `SELECT * FROM contacts WHERE id=? AND (sharer_id=? OR guardian_id=?)`,
      +r[1],
      me.id,
      me.id,
    );
    if (!c) return err(res, 404, "Not found");
    if (m === "DELETE") {
      run("DELETE FROM contacts WHERE id=?", c.id);
      push(c.sharer_id, { type: "refresh" });
      if (c.guardian_id) push(c.guardian_id, { type: "refresh" });
      return ok(res);
    }
    if (m === "PATCH") {
      // only the sharer controls what is shared
      if (c.sharer_id !== me.id)
        return err(res, 403, "Only the person sharing can change permissions");
      if (LEVELS.includes(b.level))
        run("UPDATE contacts SET level=? WHERE id=?", b.level, c.id);
      if (typeof b.paused === "boolean")
        run("UPDATE contacts SET paused=? WHERE id=?", b.paused ? 1 : 0, c.id);
      if (c.guardian_id) push(c.guardian_id, { type: "refresh" });
      return ok(res);
    }
  }

  // status
  if (p === "/api/status" && m === "POST") {
    const label = str(b.label, 280);
    if (!label) return err(res, 400, "Status text required");
    const id = Number(
      run(
        "INSERT INTO statuses(user_id,label,at) VALUES(?,?,?)",
        me.id,
        label,
        now(),
      ).lastInsertRowid,
    );
    for (const g of guardiansOf(me.id))
      notify(
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
      ...q(
        `SELECT sharer_id FROM contacts WHERE guardian_id=? AND status='accepted' AND paused=0`,
        me.id,
      ).map((x) => x.sharer_id),
    ];
    const rows = q(
      `SELECT s.id,s.label,s.at,u.name,u.id userId FROM statuses s JOIN users u ON u.id=s.user_id WHERE s.user_id IN (${ids.map(() => "?").join(",")}) ORDER BY s.at DESC LIMIT 30`,
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
    const was = one(
      "SELECT sharing FROM location WHERE user_id=?",
      me.id,
    ).sharing;
    run(
      "UPDATE location SET sharing=1,lat=?,lng=?,acc=?,at=? WHERE user_id=?",
      lat,
      lng,
      num(b.acc),
      now(),
      me.id,
    );
    if (!was)
      for (const g of guardiansOf(me.id, "location"))
        notify(
          g,
          "location_started",
          "Location sharing started",
          `${me.name} is sharing live location`,
        );
    for (const g of guardiansOf(me.id, "location"))
      push(g, { type: "location", userId: me.id });
    return ok(res);
  }
  if (p === "/api/location/stop" && m === "POST") {
    run(
      "UPDATE location SET sharing=0,lat=NULL,lng=NULL,acc=NULL WHERE user_id=?",
      me.id,
    );
    for (const g of guardiansOf(me.id, "location")) {
      notify(
        g,
        "location_stopped",
        "Location sharing stopped",
        `${me.name} stopped sharing`,
      );
    }
    return ok(res);
  }
  if ((r = p.match(/^\/api\/location\/current\/(\d+)$/)) && m === "GET") {
    const uid = +r[1];
    if (!canView(me.id, uid, "location"))
      return err(res, 403, "Not authorised");
    if (uid !== me.id)
      run(
        "INSERT INTO notifications(user_id,type,title,body,at,read) VALUES(?,?,?,?,?,1)",
        uid,
        "audit",
        "Location viewed",
        `${me.name} viewed your location`,
        now(),
      );
    const l = one(
      "SELECT sharing,lat,lng,acc,at FROM location WHERE user_id=?",
      uid,
    );
    return ok(res, { location: l && l.sharing ? l : null });
  }

  // emergency
  if (p === "/api/emergency" && m === "POST") {
    const l =
      one("SELECT lat,lng,acc,at FROM location WHERE user_id=?", me.id) || {};
    const id = Number(
      run(
        "INSERT INTO alerts(user_id,lat,lng,acc,loc_at,at) VALUES(?,?,?,?,?,?)",
        me.id,
        l.lat ?? null,
        l.lng ?? null,
        l.acc ?? null,
        l.at ?? null,
        now(),
      ).lastInsertRowid,
    );
    for (const g of guardiansOf(me.id, "status", true))
      notify(
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
    const a = one("SELECT * FROM alerts WHERE id=?", +r[1]);
    if (!a) return err(res, 404, "Not found");
    const owner = a.user_id === me.id,
      guardian = guardiansOf(a.user_id, "status", true).includes(me.id);
    if (r[2] === "cancel" && owner)
      run(`UPDATE alerts SET state='cancelled' WHERE id=?`, a.id);
    else if (r[2] === "acknowledge" && guardian)
      run(
        `UPDATE alerts SET state='acknowledged', ack_by=? WHERE id=?`,
        me.id,
        a.id,
      );
    else if (r[2] === "resolve" && (owner || guardian))
      run(`UPDATE alerts SET state='resolved' WHERE id=?`, a.id);
    else return err(res, 403, "Not authorised");
    for (const u of [a.user_id, ...guardiansOf(a.user_id, "status", true)])
      if (u !== me.id)
        notify(
          u,
          "emergency_update",
          `Emergency ${r[2]}`,
          `${me.name}: ${r[2]}`,
          a.id,
        );
    return ok(res);
  }
  if (p === "/api/emergency/active" && m === "GET") {
    const mine = q(
      `SELECT * FROM alerts WHERE user_id=? AND state='active'`,
      me.id,
    );
    const others = q(
      `SELECT a.*,u.name FROM alerts a JOIN users u ON u.id=a.user_id JOIN contacts c ON c.sharer_id=a.user_id WHERE c.guardian_id=? AND c.status='accepted' AND a.state IN ('active','acknowledged')`,
      me.id,
    );
    return ok(res, { mine, others });
  }

  // notifications
  if (p === "/api/notifications" && m === "GET") {
    const items = q(
      `SELECT * FROM notifications WHERE user_id=? AND type!='audit' ORDER BY at DESC LIMIT 50`,
      me.id,
    );
    return ok(res, { items, unread: items.filter((i) => !i.read).length });
  }
  if (p === "/api/notifications/read" && m === "POST") {
    run("UPDATE notifications SET read=1 WHERE user_id=?", me.id);
    return ok(res);
  }

  return err(res, 404, "Unknown endpoint");
}

http
  .createServer(async (req, res) => {
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
      if (!res.headersSent)
        err(
          res,
          500,
          e.message === "bad json" ? "Invalid JSON" : "Server error",
        );
    }
  })
  .listen(PORT, () =>
    console.log(`SafeLoop running on http://localhost:${PORT}`),
  );
