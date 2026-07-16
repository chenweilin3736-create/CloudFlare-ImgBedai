import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { verifyPassword, rehashIfNeeded } from "../../utils/auth/passwordHash.js";
import { createSession } from "../../utils/auth/sessionManager.js";
import { getDatabase } from "../../utils/databaseAdapter.js";

// 速率限制配置
const RATE_LIMIT_PREFIX = 'rate@userLogin@';
const MAX_FAILED_ATTEMPTS = 10;
const RATE_LIMIT_WINDOW = 900; // 15分钟

export async function onRequestPost(context) {
    const { request, env } = context;

    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const failKey = `${RATE_LIMIT_PREFIX}${clientIp}`;

    const db = getDatabase(env);
    const failCount = parseInt(await db.get(failKey) || '0', 10);
    if (failCount >= MAX_FAILED_ATTEMPTS) {
        return new Response(JSON.stringify({ error: 'Too many login attempts.' }), {
            status: 429,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    let body;
    try {
        body = await request.json();
    } catch {
        return new Response(JSON.stringify({ error: 'Invalid request body' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }
    const authCode = body.authCode;

    // 读取安全设置
    let securityConfig;
    try {
        securityConfig = await fetchSecurityConfig(env, { throwOnError: true });
    } catch (error) {
        console.error('User login blocked because security config could not be loaded:', error);
        return new Response(JSON.stringify({ error: 'Security config unavailable' }), { status: 503 });
    }
    const rightAuthCode = securityConfig.auth.user.authCode;

    // 漏洞修复：authCode 未配置时拒绝登录，不再自动创建 session
    if (!rightAuthCode || rightAuthCode.trim() === '') {
        console.warn(`User login attempted from ${clientIp} but no authCode configured`);
        return new Response(JSON.stringify({
            error: 'User authCode not configured',
            hint: 'Please configure authCode in security settings or set AUTH_CODE environment variable.'
        }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // 验证 authCode（兼容明文、SHA-256 和 PBKDF2 三种存储格式）
    const isValid = await verifyPassword(authCode, rightAuthCode);
    if (!isValid) {
        await db.put(failKey, String(failCount + 1), { expirationTtl: RATE_LIMIT_WINDOW });
        return new Response(JSON.stringify({ error: 'Invalid authCode' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // 登录成功后清除失败计数并升级哈希
    await db.delete(failKey);
    await rehashIfNeeded(getDatabase(env), authCode, rightAuthCode, 'auth.user.authCode');

    // 创建会话并通过 HttpOnly Cookie 返回
    const { cookie } = await createSession(env, 'user');

    return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': cookie,
        },
    });
}
