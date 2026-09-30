const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const INVITE_CODE = process.env.GIFT_INVITE_CODE || 'gift123';
// 数据文件路径：默认项目内 data.json；部署到 PaaS 时可指向持久盘，如 /data/data.json
const DATA_FILE = process.env.GIFT_DATA_FILE || path.join(__dirname, 'data.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

function loadData() {
  try {
    const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return { users: d.users || {}, sessions: d.sessions || {}, gifts: d.gifts || [] };
  } catch (e) {
    return { users: {}, sessions: {}, gifts: [] };
  }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function newToken() {
  return crypto.randomBytes(16).toString('hex');
}

function hashPassword(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 10000, 32, 'sha256').toString('hex');
}

function secureEqual(a, b) {
  const x = Buffer.from(a), y = Buffer.from(b);
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(c => {
    const i = c.indexOf('=');
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}

function sendJson(res, code, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  }, extraHeaders || {}));
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

// ================= 短信验证码 =================
// 验证码内存存储：phone -> { code, expires, purpose, lastSent, attempts }
const codeStore = new Map();
const PHONE_RE = /^1[3-9]\d{9}$/;

function findUserByPhone(data, phone) {
  for (const [name, u] of Object.entries(data.users)) {
    if (u.phone === phone) return name;
  }
  return null;
}

function maskPhone(p) {
  return p ? p.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2') : p;
}

// 是否处于测试模式：没有配置真实短信平台的密钥时，验证码打到控制台 + 返回给页面
const SMS_CONFIGURED = !!(process.env.SMS_ACCESS_KEY_ID && process.env.SMS_ACCESS_KEY_SECRET);
async function sendSms(phone, code, purpose) {
  if (SMS_CONFIGURED) {
    // TODO: 接入真实短信平台（阿里云/腾讯云），用 process.env 中的密钥调用其 API
    // 例如阿里云 SendSms(PhoneNumbers=phone, SignName=..., TemplateCode=..., TemplateParam=JSON.stringify({code}))
    // 成功后 return { dev: false };
  }
  console.log(`\n📱 [短信-测试模式] 发往 ${phone} 的验证码(${purpose}): ${code}\n`);
  return { dev: !SMS_CONFIGURED };
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.mp4': 'video/mp4',
  '.jpg': 'image/jpeg',
  '.png': 'image/png'
};

// 生日工具：bd = {month, day} 或 null
function getBeijingDate() {
  const d = new Date();
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: 'numeric', day: 'numeric',
    hour: 'numeric', minute: 'numeric', second: 'numeric',
    hour12: false
  });
  const parts = fmt.formatToParts(d);
  const get = (type) => Number(parts.find(p => p.type === type).value);
  return {
    year: get('year'), month: get('month'), day: get('day'),
    hour: get('hour'), minute: get('minute'), second: get('second')
  };
}
function birthdayInfo(bd) {
  if (!bd || !bd.month || !bd.day) return { set: false, days: null, isToday: false, target: null };
  const bj = getBeijingDate();
  const isToday = (bj.month === bd.month) && (bj.day === bd.day);
  let targetYear = bj.year;
  const hasPassed = (bj.month > bd.month) || (bj.month === bd.month && bj.day > bd.day);
  if (hasPassed) targetYear++;
  const target = Date.UTC(targetYear, bd.month - 1, bd.day, -8, 0, 0);
  const days = Math.max(0, Math.ceil((target - Date.now()) / 86400000));
  return { set: true, days, isToday, target };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  const cookies = parseCookies(req);
  let claimerToken = cookies['claimer_token'];
  const setCookie = [];
  if (!claimerToken) {
    claimerToken = newToken();
    setCookie.push(`claimer_token=${claimerToken}; Path=/; Max-Age=31536000; SameSite=Lax`);
  }

  // 反向代理(HTTPS)下自动给 Cookie 加 Secure
  const isHttps = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  const secure = s => isHttps ? s + '; Secure' : s;
  const head = () => setCookie.length ? { 'Set-Cookie': setCookie.map(secure) } : {};
  const headWith = extra => { const arr = setCookie.concat(extra || []).map(secure); return arr.length ? { 'Set-Cookie': arr } : {}; };

  if (pathname.startsWith('/api/')) {
    try {
      const data = loadData();

      // ---- 注册（邀请码） ----
      if (pathname === '/api/register' && req.method === 'POST') {
        const body = await readBody(req);
        const username = (body.username || '').trim();
        const password = (body.password || '');
        const invite = (body.invite || '').trim();
        const phone = (body.phone || '').trim();
        const code = (body.code || '').trim();
        if (invite !== INVITE_CODE) return sendJson(res, 403, { error: '邀请码错误' }, head());
        if (!/^[\w\u4e00-\u9fa5]{2,20}$/.test(username)) return sendJson(res, 400, { error: '用户名需 2-20 位（字母/数字/下划线/中文）' }, head());
        if (password.length < 4) return sendJson(res, 400, { error: '密码至少 4 位' }, head());
        if (data.users[username]) return sendJson(res, 409, { error: '用户名已被注册' }, head());
        if (phone) {
          if (!PHONE_RE.test(phone)) return sendJson(res, 400, { error: '手机号格式不正确' }, head());
          if (findUserByPhone(data, phone)) return sendJson(res, 409, { error: '该手机号已绑定其他账号' }, head());
          const entry = codeStore.get(phone);
          if (!entry || entry.purpose !== 'register' || Date.now() > entry.expires) return sendJson(res, 400, { error: '验证码不存在或已过期' }, head());
          if (entry.attempts >= 5) return sendJson(res, 429, { error: '尝试次数过多，请重新获取' }, head());
          if (entry.code !== code) { entry.attempts++; return sendJson(res, 400, { error: '验证码错误' }, head()); }
        }
        const salt = newToken();
        data.users[username] = { salt, hash: hashPassword(password, salt), birthday: null, phone: phone || null, created: Date.now() };
        if (phone) codeStore.delete(phone);
        const session = newToken();
        data.sessions[session] = username;
        saveData(data);
        const hd = headWith([`gift_session=${session}; Path=/; Max-Age=2592000; SameSite=Lax`]);
        return sendJson(res, 201, { ok: true, user: username }, hd);
      }

      // ---- 登录 ----
      if (pathname === '/api/login' && req.method === 'POST') {
        const body = await readBody(req);
        const username = (body.username || '').trim();
        const password = (body.password || '');
        const u = data.users[username];
        if (!u || !secureEqual(hashPassword(password, u.salt), u.hash)) return sendJson(res, 401, { error: '用户名或密码错误' }, head());
        const session = newToken();
        data.sessions[session] = username;
        saveData(data);
        const hd = headWith([`gift_session=${session}; Path=/; Max-Age=2592000; SameSite=Lax`]);
        return sendJson(res, 200, { ok: true, user: username }, hd);
      }

      // ---- 登出 ----
      if (pathname === '/api/logout' && req.method === 'POST') {
        const t = cookies['gift_session'];
        if (t && data.sessions[t]) { delete data.sessions[t]; saveData(data); }
        const hd = headWith(['gift_session=; Path=/; Max-Age=0']);
        return sendJson(res, 200, { ok: true }, hd);
      }

      // ---- 当前用户 ----
      const currentUser = () => (cookies['gift_session'] && data.sessions[cookies['gift_session']]) || null;
      const me = currentUser();

      // ---- 发送验证码 ----
      if (pathname === '/api/send-code' && req.method === 'POST') {
        const body = await readBody(req);
        const phone = (body.phone || '').trim();
        const purpose = body.purpose || 'login';
        if (!PHONE_RE.test(phone)) return sendJson(res, 400, { error: '手机号格式不正确' }, head());
        if (!['login', 'bind', 'reset', 'register'].includes(purpose)) return sendJson(res, 400, { error: '参数错误' }, head());
        const boundTo = findUserByPhone(data, phone);
        if ((purpose === 'login' || purpose === 'reset') && !boundTo) return sendJson(res, 400, { error: '该手机号还没有绑定账号' }, head());
        if (purpose === 'bind') {
          if (!me) return sendJson(res, 401, { error: '请先登录' }, head());
          if (boundTo && boundTo !== me) return sendJson(res, 409, { error: '该手机号已绑定其他账号' }, head());
        }
        if (purpose === 'register' && boundTo) return sendJson(res, 409, { error: '该手机号已绑定其他账号' }, head());
        const now = Date.now();
        const prev = codeStore.get(phone);
        if (prev && prev.purpose === purpose && now - prev.lastSent < 60000) {
          return sendJson(res, 429, { error: '发送太频繁，请 60 秒后再试' }, head());
        }
        const code = String(crypto.randomInt(100000, 1000000));
        codeStore.set(phone, { code, expires: now + 5 * 60000, purpose, lastSent: now, attempts: 0 });
        const sent = await sendSms(phone, code, purpose);
        const resp = { ok: true };
        if (sent.dev) resp.devCode = code;
        return sendJson(res, 200, resp, head());
      }

      // ---- 手机验证码登录 ----
      if (pathname === '/api/login-phone' && req.method === 'POST') {
        const body = await readBody(req);
        const phone = (body.phone || '').trim();
        const code = (body.code || '').trim();
        const entry = codeStore.get(phone);
        if (!entry || entry.purpose !== 'login' || Date.now() > entry.expires) return sendJson(res, 400, { error: '验证码不存在或已过期' }, head());
        if (entry.attempts >= 5) return sendJson(res, 429, { error: '尝试次数过多，请重新获取' }, head());
        if (entry.code !== code) { entry.attempts++; return sendJson(res, 400, { error: '验证码错误' }, head()); }
        codeStore.delete(phone);
        const username = findUserByPhone(data, phone);
        if (!username) return sendJson(res, 400, { error: '该手机号未绑定账号' }, head());
        const session = newToken();
        data.sessions[session] = username;
        saveData(data);
        const hd = headWith([`gift_session=${session}; Path=/; Max-Age=2592000; SameSite=Lax`]);
        return sendJson(res, 200, { ok: true, user: username }, hd);
      }

      // ---- 绑定手机号 ----
      if (pathname === '/api/bind-phone' && req.method === 'POST') {
        if (!me) return sendJson(res, 401, { error: '请先登录' }, head());
        const body = await readBody(req);
        const phone = (body.phone || '').trim();
        const code = (body.code || '').trim();
        const entry = codeStore.get(phone);
        if (!entry || entry.purpose !== 'bind' || Date.now() > entry.expires) return sendJson(res, 400, { error: '验证码不存在或已过期' }, head());
        if (entry.attempts >= 5) return sendJson(res, 429, { error: '尝试次数过多，请重新获取' }, head());
        if (entry.code !== code) { entry.attempts++; return sendJson(res, 400, { error: '验证码错误' }, head()); }
        const boundTo = findUserByPhone(data, phone);
        if (boundTo && boundTo !== me) return sendJson(res, 409, { error: '该手机号已绑定其他账号' }, head());
        codeStore.delete(phone);
        data.users[me].phone = phone;
        saveData(data);
        return sendJson(res, 200, { ok: true, phone: maskPhone(phone) }, head());
      }

      // ---- 忘记密码：用手机验证码重置 ----
      if (pathname === '/api/reset-password' && req.method === 'POST') {
        const body = await readBody(req);
        const phone = (body.phone || '').trim();
        const code = (body.code || '').trim();
        const newPassword = body.newPassword || '';
        const entry = codeStore.get(phone);
        if (!entry || entry.purpose !== 'reset' || Date.now() > entry.expires) return sendJson(res, 400, { error: '验证码不存在或已过期' }, head());
        if (entry.attempts >= 5) return sendJson(res, 429, { error: '尝试次数过多，请重新获取' }, head());
        if (entry.code !== code) { entry.attempts++; return sendJson(res, 400, { error: '验证码错误' }, head()); }
        if (newPassword.length < 4) return sendJson(res, 400, { error: '新密码至少 4 位' }, head());
        const username = findUserByPhone(data, phone);
        if (!username) return sendJson(res, 400, { error: '该手机号未绑定账号' }, head());
        codeStore.delete(phone);
        const salt = newToken();
        data.users[username].salt = salt;
        data.users[username].hash = hashPassword(newPassword, salt);
        Object.keys(data.sessions).forEach(t => { if (data.sessions[t] === username) delete data.sessions[t]; });
        saveData(data);
        return sendJson(res, 200, { ok: true, user: username }, head());
      }

      if (pathname === '/api/me' && req.method === 'GET') {
        if (!me) return sendJson(res, 200, { user: null }, head());
        const u = data.users[me];
        return sendJson(res, 200, { user: me, birthday: u.birthday || null, countdown: birthdayInfo(u.birthday), phone: maskPhone(u.phone), hasPhone: !!u.phone }, head());
      }

      // ---- 设置生日 ----
      if (pathname === '/api/birthday' && req.method === 'POST') {
        if (!me) return sendJson(res, 401, { error: '请先登录' }, head());
        const body = await readBody(req);
        const month = Number(body.month), day = Number(body.day);
        if (!(month >= 1 && month <= 12)) return sendJson(res, 400, { error: '月份需为 1-12' }, head());
        if (!(day >= 1 && day <= 31)) return sendJson(res, 400, { error: '日期需为 1-31' }, head());
        data.users[me].birthday = { month, day };
        saveData(data);
        return sendJson(res, 200, { ok: true, birthday: { month, day }, countdown: birthdayInfo({ month, day }) }, head());
      }

      // ---- 所有用户（用于浏览） ----
      if (pathname === '/api/users' && req.method === 'GET') {
        if (!me) return sendJson(res, 401, { error: '请先登录' }, head());
        return sendJson(res, 200, { users: Object.keys(data.users) }, head());
      }

      // ---- 查看礼物清单（可指定 owner） ----
      if (pathname === '/api/gifts' && req.method === 'GET') {
        if (!me) return sendJson(res, 401, { error: '请先登录' }, head());
        const owner = url.searchParams.get('owner') || me;
        if (!data.users[owner]) return sendJson(res, 404, { error: '用户不存在' }, head());
        const reveal = (owner === me) && birthdayInfo(data.users[owner].birthday).isToday;
        const gifts = data.gifts.filter(g => g.owner === owner).map(g => ({
          id: g.id,
          name: g.name,
          love: g.love,
          price: g.price,
          description: g.description,
          comments: (g.comments || []).map(c => ({ id: c.id, text: c.text, time: c.time, mine: c.authorToken === claimerToken })),
          claimed: !!g.claimedBy,
          mine: !!(g.claimedBy && ((me && g.claimedBy.user === me) || (!g.claimedBy.user && g.claimedBy.token === claimerToken))),
          claimedByUser: (reveal && g.claimedBy) ? (g.claimedBy.user || null) : null
        }));
        return sendJson(res, 200, {
          owner,
          canEdit: owner === me,
          ownerInfo: { username: owner, birthday: data.users[owner].birthday, countdown: birthdayInfo(data.users[owner].birthday) },
          gifts
        }, head());
      }

      // ---- 添加礼物（加到自己的清单） ----
      if (pathname === '/api/gifts' && req.method === 'POST') {
        if (!me) return sendJson(res, 401, { error: '请先登录' }, head());
        const body = await readBody(req);
        const name = (body.name || '').trim();
        const love = Number(body.love);
        const price = (body.price || '').toString().trim().replace(/^¥\s*/, '');
        const description = (body.description || '').trim();
        if (!name) return sendJson(res, 400, { error: '礼物名称不能为空' }, head());
        if (!(love >= 1 && love <= 5)) return sendJson(res, 400, { error: '喜爱程度需为 1-5' }, head());
        const gift = { id: newToken(), owner: me, name, love, price, description, comments: [], claimedBy: null };
        data.gifts.push(gift);
        saveData(data);
        return sendJson(res, 201, { ok: true, gift: { id: gift.id, name: gift.name, love, price, description, comments: [], claimed: false, mine: false } }, head());
      }

      // ---- 评价 ----
      const giftMatch = pathname.match(/^\/api\/gifts\/([^/]+)\/comments$/);
      if (giftMatch && req.method === 'POST') {
        const body = await readBody(req);
        const text = (body.text || '').trim();
        if (!text) return sendJson(res, 400, { error: '评价内容不能为空' }, head());
        const gift = data.gifts.find(g => g.id === giftMatch[1]);
        if (!gift) return sendJson(res, 404, { error: '礼物不存在' }, head());
        const comment = { id: newToken(), text, time: Date.now(), authorToken: claimerToken };
        gift.comments = gift.comments || [];
        gift.comments.push(comment);
        saveData(data);
        return sendJson(res, 201, { ok: true, comment: { id: comment.id, text: comment.text, time: comment.time, mine: true } }, head());
      }

      // ---- 修改/删除评价 ----
      const commentEdit = pathname.match(/^\/api\/gifts\/([^/]+)\/comments\/([^/]+)$/);
      if (commentEdit) {
        const giftId = commentEdit[1], cid = commentEdit[2];
        const gift = data.gifts.find(g => g.id === giftId);
        if (!gift) return sendJson(res, 404, { error: '礼物不存在' }, head());
        const comment = (gift.comments || []).find(c => c.id === cid);
        if (!comment) return sendJson(res, 404, { error: '评价不存在' }, head());
        if (req.method === 'PATCH') {
          if (comment.authorToken !== claimerToken) return sendJson(res, 403, { error: '只能修改自己的评价' }, head());
          const body = await readBody(req);
          const text = (body.text || '').trim();
          if (!text) return sendJson(res, 400, { error: '评价内容不能为空' }, head());
          comment.text = text;
          saveData(data);
          return sendJson(res, 200, { ok: true, comment: { id: comment.id, text: comment.text, time: comment.time, mine: true } }, head());
        }
        if (req.method === 'DELETE') {
          const allowed = comment.authorToken === claimerToken || gift.owner === me;
          if (!allowed) return sendJson(res, 403, { error: '无权删除此评价' }, head());
          gift.comments = (gift.comments || []).filter(c => c.id !== cid);
          saveData(data);
          return sendJson(res, 200, { ok: true }, head());
        }
      }

      // ---- 认领 ----
      const claimMatch = pathname.match(/^\/api\/gifts\/([^/]+)\/claim$/);
      if (claimMatch && req.method === 'POST') {
        const gift = data.gifts.find(g => g.id === claimMatch[1]);
        if (!gift) return sendJson(res, 404, { error: '礼物不存在' }, head());
        const isMine = gift.claimedBy && (
          (me && gift.claimedBy.user === me) ||
          (!gift.claimedBy.user && gift.claimedBy.token === claimerToken)
        );
        if (isMine) {
          gift.claimedBy = null;
          saveData(data);
          return sendJson(res, 200, { ok: true, claimed: false, mine: false }, head());
        }
        if (gift.claimedBy) {
          return sendJson(res, 409, { error: '这个礼物已经被别人认领啦' }, head());
        }
        gift.claimedBy = { token: claimerToken, user: me || null, time: Date.now() };
        saveData(data);
        return sendJson(res, 200, { ok: true, claimed: true, mine: true }, head());
      }

      // ---- 删除礼物（仅本人） ----
      const delMatch = pathname.match(/^\/api\/gifts\/([^/]+)$/);
      if (delMatch && req.method === 'DELETE') {
        const gift = data.gifts.find(g => g.id === delMatch[1]);
        if (!gift) return sendJson(res, 404, { error: '礼物不存在' }, head());
        if (gift.owner !== me) return sendJson(res, 403, { error: '只能删除自己的礼物' }, head());
        data.gifts = data.gifts.filter(g => g.id !== delMatch[1]);
        saveData(data);
        return sendJson(res, 200, { ok: true }, head());
      }

      return sendJson(res, 404, { error: 'Not Found' }, head());
    } catch (e) {
      console.error('API error:', e);
      return sendJson(res, 500, { error: '服务器错误' }, head());
    }
  }

  // 静态文件
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.join(PUBLIC_DIR, path.normalize(filePath));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Not Found');
    }
    const ext = path.extname(filePath).toLowerCase();
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream' };
    if (setCookie.length) headers['Set-Cookie'] = setCookie;
    res.writeHead(200, headers);
    res.end(content);
  });
});

server.listen(PORT, () => {
  console.log(`🎁 礼物清单已启动: http://localhost:${PORT}`);
  console.log(`   注册邀请码: ${INVITE_CODE}  (可用环境变量 GIFT_INVITE_CODE 修改)`);
});
