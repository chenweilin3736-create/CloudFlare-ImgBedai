import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { verifyPassword, rehashIfNeeded } from "../../utils/auth/passwordHash.js";
import { createSession } from "../../utils/auth/sessionManager.js";
import { getDatabase } from "../../utils/databaseAdapter.js";

// 速率限制配置
const RATE_LIMIT_PREFIX = 'rate@adminLogin@';
const MAX_FAILED_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW = 900; // 15分钟

export async function onRequestPost(context) {
    const { request, env } = context;

    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const failKey = `${RATE_LIMIT_PREFIX}${clientIp}`;

    // 速率限制检查
    const db = getDatabase(env);
    const failCount = parseInt(await db.get(failKey) || '0', 10);
    if (failCount >= MAX_FAILED_ATTEMPTS) {
        return new Response(JSON.stringify({ error: 'Too many login attempts. Please try again later.' }), {
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
    const { username, password } = body;

    // 读取安全设置
    let securityConfig;
    try {
        securityConfig = await fetchSecurityConfig(env, { throwOnError: true });
    } catch (error) {
        console.error('Admin login blocked because security config could not be loaded:', error);
        return new Response(JSON.stringify({ error: 'Security config unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
        });
    }
    const adminUsername = securityConfig.auth.admin.adminUsername;
    const adminPassword = securityConfig.auth.admin.adminPassword;

    const usernameConfigured = !!(adminUsername && adminUsername.trim());
    const passwordConfigured = !!(adminPassword && adminPassword.trim());
    const adminConfigured = usernameConfigured || passwordConfigured;

    // 漏洞修复：管理员未配置时拒绝登录，不再自动创建 session
    if (!adminConfigured) {
        console.warn(`Admin login attempted from ${clientIp} but no admin credentials configured`);
        return new Response(JSON.stringify({
            error: 'Admin account not configured',
            hint: 'Please set BASIC_USER/BASIC_PASS environment variables in Cloudflare Dashboard.'
        }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // 如果设置了用户名，则验证用户名
    if (usernameConfigured && username !== adminUsername) {
        await db.put(failKey, String(failCount + 1), { expirationTtl: RATE_LIMIT_WINDOW });
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // 如果设置了密码，则验证密码
    if (passwordConfigured) {
        const passwordMatch = await verifyPassword(password, adminPassword);
        if (!passwordMatch) {
            await db.put(failKey, String(failCount + 1), { expirationTtl: RATE_LIMIT_WINDOW });
            return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // 登录成功后清除失败计数并升级哈希
        await db.delete(failKey);
        await rehashIfNeeded(getDatabase(env), password, adminPassword, 'auth.admin.adminPassword');
    }

    // 创建会话并通过 HttpOnly Cookie 返回（含 CSRF token）
    const { cookie, csrfToken } = await createSession(env, 'admin', username);

    return new Response(JSON.stringify({ success: true, csrfToken }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': cookie,
        },
    });
}
