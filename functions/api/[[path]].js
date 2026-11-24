const SESSION_COOKIE = "bandup_session";
const SESSION_SECONDS = 60 * 60 * 24 * 14;
const PASSWORD_ITERATIONS = 310000;
const TEST_MAXIMUMS = { dtm: 40, college: 30, english: 150, ielts: 150 };
const TEST_ANSWERS = {
  dtm: [2, 1, 2, 1],
  college: [0, 1, 2],
  english: [0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 2, 1],
  ielts: [1, 2, 2, 1, 1, 0, 1, 1, 3, 0, 2, 0, 1, 0, 1],
};
const LESSON_ANSWERS = [
  [0, 0, 0, 0, 0], [0, 2, 1, 0, 0], [1, 0, 1, 0, 1], [0, 1, 0, 1, 0], [1, 0, 1, 0, 0],
  [1, 1, 0, 2, 0], [1, 0, 2, 0, 2], [1, 1, 1, 1, 0], [0, 1, 2, 1, 2], [1, 0, 0, 1, 0],
];

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
});
const fail = (message, status = 400) => json({ error: message }, status);
const normalizedName = (name) => name.normalize("NFKC").trim().toLocaleLowerCase("und");
const toHex = (bytes) => Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
const randomHex = (size = 32) => toHex(crypto.getRandomValues(new Uint8Array(size)));
const digest = async (text) => toHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
const constantTimeEqual = (a, b) => {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: PASSWORD_ITERATIONS }, key, 256);
  return toHex(bits);
}

function safeUser(row) {
  return row ? { id: row.id, name: row.name, role: row.role, points: row.points } : null;
}

async function readBody(request, maxBytes = 16384) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > maxBytes) throw new Error("Request is too large");
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > maxBytes) throw new Error("Request is too large");
  return JSON.parse(text || "{}");
}

async function requireSameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin || origin !== new URL(request.url).origin) return false;
  return true;
}

async function sessionUser(request, env) {
  const cookie = request.headers.get("cookie") || "";
  const token = cookie.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([a-f0-9]{64})(?:;|$)`))?.[1];
  if (!token) return null;
  const tokenHash = await digest(token);
  const row = await env.DB.prepare(
    "SELECT u.id, u.name, u.role, u.points FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?"
  ).bind(tokenHash, Date.now()).first();
  return safeUser(row);
}

function sessionCookie(token, maxAge = SESSION_SECONDS) {
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function createSession(env, userId) {
  const token = randomHex();
  const now = Date.now();
  await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)")
    .bind(await digest(token), userId, now + SESSION_SECONDS * 1000, now).run();
  return token;
}

async function authRateAllowed(request, env, action) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const row = await env.DB.prepare("SELECT window_start,attempts FROM auth_limits WHERE ip_key=? AND action=?").bind(ip, action).first();
  if (row && now - row.window_start < windowMs && row.attempts >= 8) return false;
  await env.DB.prepare(
    "INSERT INTO auth_limits(ip_key,action,window_start,attempts) VALUES(?,?,?,1) ON CONFLICT(ip_key,action) DO UPDATE SET window_start=CASE WHEN auth_limits.window_start<? THEN excluded.window_start ELSE auth_limits.window_start END, attempts=CASE WHEN auth_limits.window_start<? THEN 1 ELSE auth_limits.attempts+1 END"
  ).bind(ip, action, now, now - windowMs, now - windowMs).run();
  return true;
}

async function register(request, env) {
  if (!await authRateAllowed(request, env, "register")) return fail("Слишком много попыток. Попробуйте позже.", 429);
  let body;
  try { body = await readBody(request); } catch { return fail("Проверьте введённые данные."); }
  const name = typeof body.name === "string" ? body.name.normalize("NFKC").trim() : "";
  const nameKey = normalizedName(name);
  const password = typeof body.password === "string" ? body.password : "";
  const nameLength = Array.from(name).length;
  const passwordLength = Array.from(password).length;
  if (nameLength < 2 || nameLength > 20 || !/^[\p{L}\p{N}_ -]+$/u.test(name)) return fail("Имя должно содержать от 2 до 20 букв или цифр.");
  if (passwordLength < 8 || passwordLength > 128) return fail("Пароль должен содержать от 8 до 128 символов.");

  const salt = randomHex(16);
  const hash = await passwordHash(password, salt);
  const id = crypto.randomUUID();
  const now = Date.now();
  const role = "student";
  try {
    await env.DB.prepare("INSERT INTO users(id,name,name_key,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)")
      .bind(id, name, nameKey, salt, hash, role, now).run();
  } catch {
    return fail("Не удалось создать аккаунт. Возможно, это имя уже занято.", 409);
  }
  const token = await createSession(env, id);
  return json({ user: { id, name, role, points: 0 } }, 201, { "set-cookie": sessionCookie(token) });
}

async function createAdmin(request, env) {
  if (!await authRateAllowed(request, env, "owner-admin")) return fail("Слишком много попыток. Попробуйте позже.", 429);
  let body;
  try { body = await readBody(request); } catch { return fail("Проверьте введённые данные."); }
  const ownerKey = typeof body.ownerKey === "string" ? body.ownerKey : "";
  if (!env.ADMIN_SETUP_KEY || !constantTimeEqual(ownerKey, env.ADMIN_SETUP_KEY)) return fail("Неверный ключ владельца.", 403);
  const name = typeof body.name === "string" ? body.name.normalize("NFKC").trim() : "";
  const nameKey = normalizedName(name);
  const password = typeof body.password === "string" ? body.password : "";
  if (Array.from(name).length < 2 || Array.from(name).length > 20 || !/^[\p{L}\p{N}_ -]+$/u.test(name)) return fail("Имя должно содержать от 2 до 20 букв или цифр.");
  if (Array.from(password).length < 8 || Array.from(password).length > 128) return fail("Пароль должен содержать от 8 до 128 символов.");
  const salt = randomHex(16);
  const hash = await passwordHash(password, salt);
  const id = crypto.randomUUID();
  try {
    await env.DB.prepare("INSERT INTO users(id,name,name_key,password_salt,password_hash,role,created_at) VALUES(?,?,?,?,?,'admin',?)")
      .bind(id, name, nameKey, salt, hash, Date.now()).run();
  } catch {
    return fail("Не удалось создать аккаунт. Возможно, это имя уже занято.", 409);
  }
  return json({ ok: true }, 201);
}

async function login(request, env) {
  if (!await authRateAllowed(request, env, "login")) return fail("Слишком много попыток. Попробуйте позже.", 429);
  let body;
  try { body = await readBody(request); } catch { return fail("Проверьте введённые данные."); }
  const name = typeof body.name === "string" ? body.name.normalize("NFKC").trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (Array.from(name).length > 20 || Array.from(password).length > 128) return fail("Неверное имя или пароль.", 401);
  const row = await env.DB.prepare("SELECT id,name,role,points,password_salt,password_hash FROM users WHERE name_key=?")
    .bind(normalizedName(name)).first();
  const candidate = await passwordHash(password, row?.password_salt || "invalid-account-salt");
  if (!row || !constantTimeEqual(candidate, row.password_hash)) return fail("Неверное имя или пароль.", 401);
  const token = await createSession(env, row.id);
  return json({ user: safeUser(row) }, 200, { "set-cookie": sessionCookie(token) });
}

async function saveScore(user, env, body) {
  const kind = body.kind;
  const key = typeof body.key === "string" ? body.key : "";
  let points = Number(body.points);
  if (kind !== "test") return fail("Некорректный результат.");
  const answers = body.answers;
  const expected = TEST_ANSWERS[key];
  if (!expected || !Array.isArray(answers) || answers.length !== expected.length || answers.some((answer) => !Number.isInteger(answer) || answer < 0 || answer > 3)) return fail("Некорректный результат.");
  points = answers.reduce((score, answer, index) => score + (answer === expected[index] ? 10 : 0), 0);
  if (!Number.isInteger(points) || points < 0) return fail("Некорректный результат.");
  let maximum = 0;
  if (Object.hasOwn(TEST_MAXIMUMS, key)) maximum = TEST_MAXIMUMS[key];
  if (!maximum || points > maximum) return fail("Некорректный результат.");

  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO scores(user_id,kind,item_key,points,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(user_id,kind,item_key) DO UPDATE SET points=MAX(scores.points,excluded.points),updated_at=excluded.updated_at")
      .bind(user.id, kind, key, points, now),
    env.DB.prepare("UPDATE users SET points=MAX(0,manual_points+(SELECT COALESCE(SUM(points),0) FROM scores WHERE user_id=?)) WHERE id=?")
      .bind(user.id, user.id),
  ]);
  const row = await env.DB.prepare("SELECT points FROM users WHERE id=?").bind(user.id).first();
  return json({ points: row?.points || 0 });
}

async function completeLesson(user, env, body) {
  const lesson = Number(body.lesson);
  const answers = body.answers;
  if (!Number.isInteger(lesson) || lesson < 1 || lesson > 10 || !Array.isArray(answers) || answers.length !== 5 || answers.some((answer) => !Number.isInteger(answer) || answer < 0 || answer > 2)) {
    return fail("Некорректный результат урока.");
  }
  const key = `lesson-${lesson}`;
  const current = await env.DB.prepare("SELECT points FROM scores WHERE user_id=? AND kind='lesson' AND item_key=?").bind(user.id, key).first();
  if (current?.points === 10) {
    const totals = await env.DB.prepare("SELECT points FROM users WHERE id=?").bind(user.id).first();
    return json({ points: 10, totalPoints: totals?.points || 0, perfect: true, locked: true });
  }
  const mistakes = answers.reduce((count, answer, index) => count + (answer === LESSON_ANSWERS[lesson - 1][index] ? 0 : 1), 0);
  const points = 10 - mistakes;
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO scores(user_id,kind,item_key,points,updated_at) VALUES(?,'lesson',?,?,?) ON CONFLICT(user_id,kind,item_key) DO UPDATE SET points=MAX(scores.points,excluded.points),updated_at=excluded.updated_at")
      .bind(user.id, key, points, now),
    env.DB.prepare("UPDATE users SET points=MAX(0,manual_points+(SELECT COALESCE(SUM(points),0) FROM scores WHERE user_id=?)) WHERE id=?")
      .bind(user.id, user.id),
  ]);
  const row = await env.DB.prepare("SELECT points FROM scores WHERE user_id=? AND kind='lesson' AND item_key=?").bind(user.id, key).first();
  const totals = await env.DB.prepare("SELECT points FROM users WHERE id=?").bind(user.id).first();
  return json({ points: row.points, totalPoints: totals?.points || 0, perfect: row.points === 10, locked: false });
}

async function adminUsers(env) {
  const { results } = await env.DB.prepare("SELECT id,name,role,points,created_at FROM users ORDER BY role DESC, name COLLATE NOCASE ASC").all();
  return json({ users: results || [] });
}

async function adminUpdate(request, env, user, pathname) {
  const match = pathname.match(/^\/api\/admin\/users\/([0-9a-f-]{36})(?:\/(points))?$/i);
  if (!match) return fail("Не найдено.", 404);
  const [, id, pointsPath] = match;
  if (request.method === "DELETE" && !pointsPath) {
    if (id === user.id) return fail("Нельзя удалить собственный админ-аккаунт.", 400);
    const target = await env.DB.prepare("SELECT role FROM users WHERE id=?").bind(id).first();
    if (!target || target.role !== "student") return fail("Ученика не удалось найти.", 404);
    const results = await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id),
      env.DB.prepare("DELETE FROM progress WHERE user_id=?").bind(id),
      env.DB.prepare("DELETE FROM scores WHERE user_id=?").bind(id),
      env.DB.prepare("DELETE FROM users WHERE id=? AND role='student'").bind(id),
    ]);
    return results[3]?.meta?.changes ? json({ ok: true }) : fail("Ученика не удалось найти.", 404);
  }
  if (request.method === "PATCH" && pointsPath) {
    let body;
    try { body = await readBody(request); } catch { return fail("Проверьте введённые данные."); }
    const delta = Number(body.delta);
    if (!Number.isInteger(delta) || Math.abs(delta) > 1000) return fail("Изменение должно быть от −1000 до 1000.");
    const result = await env.DB.prepare(
      "UPDATE users SET manual_points=manual_points+?, points=MAX(0,manual_points+?+(SELECT COALESCE(SUM(points),0) FROM scores WHERE user_id=?)) WHERE id=? AND role='student'"
    ).bind(delta, delta, id, id).run();
    if (!result.meta.changes) return fail("Ученика не удалось найти.", 404);
    return json({ ok: true });
  }
  return fail("Метод не поддерживается.", 405);
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method) && !await requireSameOrigin(request)) return fail("Запрос заблокирован.", 403);

  try {
    if (method === "POST" && path === "/api/auth/register") return await register(request, env);
    if (method === "POST" && path === "/api/owner/admins") return await createAdmin(request, env);
    if (method === "POST" && path === "/api/auth/login") return await login(request, env);
    if (method === "GET" && path === "/api/auth/me") return json({ user: await sessionUser(request, env) });
    if (method === "POST" && path === "/api/auth/logout") {
      const token = (request.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([a-f0-9]{64})(?:;|$)`))?.[1];
      if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
      return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
    }

    if (path === "/api/leaderboard" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT name,points FROM users WHERE role='student' ORDER BY points DESC,name COLLATE NOCASE ASC LIMIT 500").all();
      return json({ users: results || [] });
    }

    const user = await sessionUser(request, env);
    if (!user) return fail("Войдите в аккаунт.", 401);

    if (path === "/api/progress" && method === "GET") {
      const course = url.searchParams.get("course");
      if (!["english", "ielts"].includes(course)) return fail("Неизвестный курс.");
      const row = await env.DB.prepare("SELECT payload,updated_at FROM progress WHERE user_id=? AND course=?").bind(user.id, course).first();
      return json({ progress: row ? JSON.parse(row.payload) : null, updatedAt: row?.updated_at || null });
    }
    if (path === "/api/lessons" && method === "GET") {
      const { results } = await env.DB.prepare("SELECT item_key,points FROM scores WHERE user_id=? AND kind='lesson'").bind(user.id).all();
      const lessons = {};
      for (const result of results || []) {
        const n = Number(result.item_key.replace("lesson-", ""));
        if (Number.isInteger(n) && n >= 1 && n <= 10) lessons[n] = { points: result.points, perfect: result.points === 10 };
      }
      return json({ lessons });
    }
    if (path === "/api/progress" && method === "PUT") {
      let body;
      try { body = await readBody(request, 32768); } catch { return fail("Прогресс не удалось сохранить."); }
      if (!["english", "ielts"].includes(body.course) || !body.progress || typeof body.progress !== "object" || Array.isArray(body.progress)) return fail("Некорректный прогресс.");
      const payload = JSON.stringify(body.progress);
      if (payload.length > 24000) return fail("Прогресс слишком большой.");
      const updatedAt = Date.now();
      await env.DB.prepare("INSERT INTO progress(user_id,course,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id,course) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at")
        .bind(user.id, body.course, payload, updatedAt).run();
      return json({ ok: true, updatedAt });
    }
    if (path === "/api/scores" && method === "POST") {
      let body;
      try { body = await readBody(request); } catch { return fail("Некорректный результат."); }
      return await saveScore(user, env, body);
    }
    if (path === "/api/lessons/complete" && method === "POST") {
      let body;
      try { body = await readBody(request); } catch { return fail("Некорректный результат."); }
      return await completeLesson(user, env, body);
    }
    if (path === "/api/admin/users" && method === "GET") {
      if (user.role !== "admin") return fail("Доступ только для администратора.", 403);
      return await adminUsers(env);
    }
    if (path.startsWith("/api/admin/users/") && ["PATCH", "DELETE"].includes(method)) {
      if (user.role !== "admin") return fail("Доступ только для администратора.", 403);
      return await adminUpdate(request, env, user, path);
    }
    return fail("Не найдено.", 404);
  } catch (error) {
    console.error("BandUp API error", error?.message || "unknown error");
    return fail("Сервис временно недоступен. Попробуйте позже.", 500);
  }
}
