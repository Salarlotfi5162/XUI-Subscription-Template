import express from "express";
import fetch from "node-fetch";
import qs from "querystring";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { toJalaali } from "jalaali-js";
import https from 'https';
import http from 'http';
import speakeasy from 'speakeasy';
import mysql from 'mysql2/promise';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

// Database pool will be initialized after loading config

// Database pool will be initialized after loading config

const app = express();

// Security Settings
app.disable('x-powered-by'); // Hide Express JS signature
app.use(helmet({
    contentSecurityPolicy: false, // Disabling CSP for now to not break dynamic template rendering/inline scripts
    crossOriginEmbedderPolicy: false
}));

// Rate Limiting (Prevent DDoS and Brute Force)
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    limit: 60, // Limit each IP to 60 requests per windowMs
    standardHeaders: 'draft-7', // draft-6: RateLimit-* headers; draft-7: combined RateLimit header
    legacyHeaders: false, // Disable the X-RateLimit-* headers
    message: { error: "تعداد درخواست‌های شما بیش از حد مجاز است. لطفاً کمی صبر کنید." }
});

app.use(limiter);

const CONFIG_FILE_NAME = "dvhost.config";
const BROWSER_KEYWORDS = ['Mozilla', 'Chrome', 'Safari', 'Edge', 'Opera', 'Firefox', 'Trident', 'WebKit'];

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const loadConfig = () => {
    const configFile = path.join(__dirname, CONFIG_FILE_NAME);
    if (!fs.existsSync(configFile)) {
        console.error("Error: Configuration file 'dvhost.config' not found!");
        process.exit(1);
    }

    return fs.readFileSync(configFile, "utf-8")
        .split("\n")
        .reduce((acc, line) => {
            const [key, value] = line.split("=").map(item => item.trim());
            if (key && value) acc[key] = value;
            return acc;
        }, {});
};

const config = loadConfig();

const {
    HOST: dvhost_host = 'localhost',
    PORT: dvhost_port = '8080',
    PATH: dvhost_path = '',
    USERNAME = '',
    PASSWORD = '',
    PROTOCOL = 'http',
    SUBSCRIPTION = '',
    PUBLIC_KEY_PATH = '',
    PRIVATE_KEY_PATH = '',
    TEMPLATE_NAME = 'default',
    DEFAULT_LANG = 'en',
    SUB_HTTP_PORT = '3000',
    SUB_HTTPS_PORT = '443',
    TELEGRAM_URL = '',
    WHATSAPP_URL = '',
    Backup_link: BACKUP_LINK = '',
    TOTP_SECRET = '',
    TWO_FACTOR = 'false',
    DB_HOST = '',
    DB_NAME = '',
    DB_USER = '',
    DB_PASS = ''
} = config;

let dbPool = null;
if (DB_HOST && DB_NAME && DB_USER && DB_PASS) {
    try {
        dbPool = mysql.createPool({
            host: DB_HOST,
            user: DB_USER,
            password: DB_PASS,
            database: DB_NAME,
            charset: 'utf8mb4',
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });
        console.log("Database pool initialized successfully.");
    } catch (e) {
        console.error("Failed to initialize database pool:", e.message);
    }
}

const convertToJalali = (timestamp) => {
    const date = new Date(timestamp);
    const { jy, jm, jd } = toJalaali(date.getFullYear(), date.getMonth() + 1, date.getDate());
    return `${jy}/${jm}/${jd}`;
};

const isBrowserRequest = (userAgent = '') =>
    BROWSER_KEYWORDS.some(keyword => userAgent.includes(keyword));

app.use(express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, `views/templates/${TEMPLATE_NAME}`));
app.set("view engine", "ejs");

const fetchWithRetry = async (url, options, retries = 3) => {
    try {
        const response = await fetch(url, options);
        if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
        return response;
    } catch (error) {
        if (retries <= 0) throw error;
        return fetchWithRetry(url, options, retries - 1);
    }
};

let cachedCookie = null;
let loginPromise = null;

const performLogin = async () => {
    let loginPayload = {
        username: USERNAME,
        password: PASSWORD
    };

    if (TWO_FACTOR === 'true' && TOTP_SECRET) {
        loginPayload.twoFactorCode = speakeasy.totp({
            secret: TOTP_SECRET,
            encoding: 'base32',
            window: 1
        });
    }

    const response = await fetchWithRetry(`${PROTOCOL}://${dvhost_host}:${dvhost_port}/${dvhost_path}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: qs.stringify(loginPayload),
    });

    if (!response.ok) throw new Error("Login request failed.");

    const result = await response.json();
    if (!result.success) throw new Error(result.msg || "Login unsuccessful");

    cachedCookie = response.headers.get("set-cookie");
    return cachedCookie;
};

const getCookie = async () => {
    if (cachedCookie) return cachedCookie;
    if (!loginPromise) {
        loginPromise = performLogin().finally(() => loginPromise = null);
    }
    return loginPromise;
};

const xuiApiCall = async (endpoint, method = "GET") => {
    let cookie = await getCookie();
    let res = await fetchWithRetry(`${PROTOCOL}://${dvhost_host}:${dvhost_port}/${dvhost_path}${endpoint}`, {
        method,
        headers: { cookie, "Accept": "application/json" }
    });

    let data = await res.json();
    if (!data.success && (data.msg && data.msg.includes("login") || res.status === 401 || res.status === 403)) {
        cachedCookie = null; // Invalidate current session
        cookie = await getCookie(); // Get fresh session
        res = await fetchWithRetry(`${PROTOCOL}://${dvhost_host}:${dvhost_port}/${dvhost_path}${endpoint}`, {
            method,
            headers: { cookie, "Accept": "application/json" }
        });
        data = await res.json();
    }
    return data;
};

app.get(`/${SUBSCRIPTION.split('/')[3]}/:subId`, async (req, res) => {
    try {
        const { subId: targetSubId } = req.params;

        // Input Validation: Ensure subId contains only alphanumeric, dash, and underscore
        if (!/^[a-zA-Z0-9_-]+$/.test(targetSubId)) {
            return res.status(400).json({ error: "شناسه نامعتبر است." });
        }

        const userAgent = req.headers['user-agent'] || '';

        const [listResult, suburl_content] = await Promise.all([
            xuiApiCall('/panel/api/inbounds/list'),
            fetchUrlContent(`${SUBSCRIPTION}${targetSubId}`)
        ]);

        const foundClient = listResult.obj
            .flatMap(inbound => JSON.parse(inbound.settings).clients)
            .find(client => client.subId === targetSubId);

        if (!foundClient) return res.status(404).json({ message: "No object found with the specified subId." });

        const trafficData = await xuiApiCall(`/panel/api/inbounds/getClientTraffics/${foundClient.email}`);

        const expiryTimeJalali = convertToJalali(trafficData.obj.expiryTime);
        const suburl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;

        // --- Added Logic for Premium UI ---
        // 1. Calculate advanced UI data from trafficData & listResult
        let inboundsCount = 0;
        let lastConnectionTime = 0; // Will hold the max lastOnline among all inbounds

        let traffic = { up: 0, down: 0, total: 0, expiryTime: 0 };
        let firstTrafficSet = false;

        listResult.obj.forEach(inbound => {
            const settings = JSON.parse(inbound.settings);
            const client = settings.clients.find(c => c.subId === targetSubId);
            if (client) {
                inboundsCount++;
            }

            // In Sanaei, clientStats array holds the traffic/online status for each client
            if (inbound.clientStats) {
                // Find the specific email for this inbound since Sanaei might append _inbX to the email
                const clientEmailInThisInbound = client ? client.email : null;
                const cStats = inbound.clientStats.find(c => c.email === clientEmailInThisInbound);
                if (cStats) {
                    if (cStats.lastOnline && cStats.lastOnline > lastConnectionTime) {
                        lastConnectionTime = cStats.lastOnline;
                    }

                    // Native Sanaei Logic Conversion:
                    if (!firstTrafficSet) {
                        traffic.up = cStats.up || 0;
                        traffic.down = cStats.down || 0;
                        traffic.total = cStats.total || 0;
                        if (cStats.expiryTime > 0) {
                            traffic.expiryTime = cStats.expiryTime;
                        }
                        firstTrafficSet = true;
                    } else {
                        traffic.up += cStats.up || 0;
                        traffic.down += cStats.down || 0;
                        if (traffic.total === 0 || cStats.total === 0) {
                            traffic.total = 0;
                        } else {
                            traffic.total += cStats.total || 0;
                        }
                        if (cStats.expiryTime !== traffic.expiryTime) {
                            traffic.expiryTime = 0;
                        }
                    }
                }
            } else if (client && client.lastOnline) {
                // Fallback in case they store it directly in the client settings rather than clientStats
                if (client.lastOnline > lastConnectionTime) {
                    lastConnectionTime = client.lastOnline;
                }
            }
        });

        const finalUp = traffic.up;
        const finalDown = traffic.down;
        const finalTotal = traffic.total;

        // Use exact expiry time from manually grouped info. Overwrite the API single value
        if (firstTrafficSet) {
            trafficData.obj.expiryTime = traffic.expiryTime;
        }

        const totalUsageGB = ((finalUp + finalDown) / 1073741824).toFixed(2);
        const baseLimitGB = inboundsCount > 0 ? ((finalTotal / inboundsCount) / 1073741824).toFixed(2) : 0;
        const remainingUsageGB = inboundsCount > 0 ? Math.max(0, baseLimitGB - totalUsageGB).toFixed(2) : 0;

        let dbUsername = targetSubId;
        if (foundClient && foundClient.email) {
            dbUsername = foundClient.email.split('_inb')[0].trim();
        }

        // ==========================================
        // Fetch Purchase Date from DB
        // ==========================================
        let purchaseDateStr = "نامشخص";
        if (dbPool) {
            try {
                const [rows] = await dbPool.execute('SELECT time_sell FROM invoice WHERE username = ? LIMIT 1', [dbUsername]);
                if (rows.length > 0 && rows[0].time_sell) {
                    const timeSell = rows[0].time_sell;
                    const pDate = new Date(timeSell * 1000);
                    const { jy, jm, jd } = toJalaali(pDate.getFullYear(), pDate.getMonth() + 1, pDate.getDate());
                    const hours = pDate.getHours().toString().padStart(2, '0');
                    const minutes = pDate.getMinutes().toString().padStart(2, '0');
                    const seconds = pDate.getSeconds().toString().padStart(2, '0');
                    purchaseDateStr = `${hours}:${minutes}:${seconds}  ${jy}/${jm < 10 ? '0' + jm : jm}/${jd < 10 ? '0' + jd : jd}`;
                }
            } catch (dbErr) {
                const logMsg = `[${new Date().toISOString()}] DB Query Error (${dbUsername}): ${dbErr.message}\n`;
                fs.appendFile(path.join(__dirname, 'db_errors.log'), logMsg, () => { });
                purchaseDateStr = "ثبت نشده"; // Clean UI fallback
            }
        } else {
            const logMsg = `[${new Date().toISOString()}] DB Connection Error (${dbUsername}): Pool is not connected.\n`;
            fs.appendFile(path.join(__dirname, 'db_errors.log'), logMsg, () => { });
            purchaseDateStr = "ثبت نشده"; // Clean UI fallback
        }

        // ==========================================
        // Fetch Last Connection Actual Time
        // ==========================================
        // As per user's logic, Sanaei provides lastOnline in milliseconds
        let lastConnectionStr = "متصل نشده";

        if (lastConnectionTime > 0) {
            // Found a valid non-zero lastOnline timestamp
            const onlineDt = new Date(lastConnectionTime); // It's already in ms
            const { jy, jm, jd } = toJalaali(onlineDt.getFullYear(), onlineDt.getMonth() + 1, onlineDt.getDate());
            const hours = onlineDt.getHours().toString().padStart(2, '0');
            const minutes = onlineDt.getMinutes().toString().padStart(2, '0');
            const seconds = onlineDt.getSeconds().toString().padStart(2, '0');
            lastConnectionStr = `${hours}:${minutes}:${seconds}  ${jy}/${jm < 10 ? '0' + jm : jm}/${jd < 10 ? '0' + jd : jd}`;
        } else {
            // Fallback heuristic if it's 0 or missing
            if ((finalUp + finalDown) > 0) {
                lastConnectionStr = "در حال استفاده (جزئیات نامشخص)";
            } else {
                lastConnectionStr = "تاکنون متصل نشده است";
            }
        }

        let daysText = "نامحدود";
        let statusText = trafficData.obj.enable ? "فعال" : "غیرفعال";
        let isExpired = false;

        if (trafficData.obj.expiryTime > 0) {
            const currentTime = Date.now();
            if (trafficData.obj.expiryTime > currentTime) {
                const remainingDays = Math.floor((trafficData.obj.expiryTime - currentTime) / (1000 * 60 * 60 * 24));
                const remainingHours = Math.floor(((trafficData.obj.expiryTime - currentTime) % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                daysText = `${remainingDays} روز, ${remainingHours} ساعت`;
            } else {
                daysText = "منقضی شده";
                statusText = "منقضی شده";
                isExpired = true;
            }
        }

        const expiryDate = trafficData.obj.expiryTime > 0 ? new Date(trafficData.obj.expiryTime).toLocaleString('fa-IR', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : "بدون تاریخ اتمام";

        // 2. Decode the suburl_content to pass actual links to the UI
        let linksArray = [];
        try {
            const decodedContent = Buffer.from(suburl_content, 'base64').toString('utf-8');
            const lines = decodedContent.split('\n').filter(line => line.trim().length > 0);

            lines.forEach(line => {
                if (line.startsWith('vless://') || line.startsWith('vmess://') || line.startsWith('trojan://')) {
                    let name = "Config";
                    try {
                        if (line.startsWith('vmess://')) {
                            const payload = Buffer.from(line.replace('vmess://', ''), 'base64').toString('utf-8');
                            const parsed = JSON.parse(payload);
                            name = parsed.ps || "Vmess Config";
                        } else {
                            const urlObj = new URL(line);
                            name = decodeURIComponent(urlObj.hash.substring(1)) || "Config";
                        }
                    } catch (e) { } // Ignore parse errors
                    linksArray.push({ name: name, link: line });
                }
            });
        } catch (e) {
            console.error("Error decoding config links for UI:", e);
        }

        let clientApp = userAgent.split(' ')[0] || "Browser"; // Try to guess app from user-agent
        if (clientApp.length > 20) clientApp = clientApp.substring(0, 20); // truncate

        if (isBrowserRequest(userAgent)) {
            return res.render("sub", {
                data: {
                    ...trafficData.obj,
                    up: finalUp,
                    down: finalDown,
                    total: finalTotal,
                    email: dbUsername, // Override the email string to not show _inb1 in the UI
                    expiryTimeJalali,
                    suburl,
                    suburl_content,
                    get_backup_link: BACKUP_LINK,
                    WHATSAPP_URL,
                    TELEGRAM_URL,
                    DEFAULT_LANG,
                    // New Premium UI fields:
                    lastConnectionStr,
                    expiryDate,
                    clientApp,
                    purchaseDateStr,
                    daysText,
                    statusText,
                    remainingUsageGB,
                    baseLimitGB,
                    totalUsageGB,
                    inboundsCount,
                    linksArray
                },
            });
        }

        const combinedContent = [BACKUP_LINK, Buffer.from(suburl_content, 'base64').toString('utf-8')]
            .filter(Boolean)
            .join('\n');

        // ==== INJECT DUMMY INFO CONFIG ====
        let finalContent = combinedContent;
        if (!isBrowserRequest(userAgent)) {
            try {
                if (inboundsCount > 0) {
                    // 3. Calculate remaining days
                    let daysText = "Unlimited";
                    if (trafficData.obj.expiryTime > 0) {
                        const currentTime = Date.now();
                        if (trafficData.obj.expiryTime > currentTime) {
                            const remainingDays = Math.floor((trafficData.obj.expiryTime - currentTime) / (1000 * 60 * 60 * 24));
                            daysText = `${remainingDays} Days`;
                        } else {
                            daysText = "Expired";
                        }
                    }

                    // 4. Create dummy config
                    const dummyName = encodeURIComponent(`📥 ${totalUsageGB}GB / ${baseLimitGB}GB | ⏳ ${daysText}`);
                    const dummyConfig = `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?path=%2F&security=none&encryption=none&type=tcp#${dummyName}\n`;

                    finalContent = dummyConfig + finalContent;
                }
            } catch (calcError) {
                console.error("Error creating dummy config:", calcError.message);
                // Fallback to normal content if something fails
            }
        }

        res.send(Buffer.from(finalContent, 'utf-8').toString('base64'));
    } catch (error) {
        const logMsg = `[${new Date().toISOString()}] Server Error (SubID: ${req.params.subId}): ${error.message}\n`;
        fs.appendFile(path.join(__dirname, 'db_errors.log'), logMsg, () => { });

        const userAgent = req.headers['user-agent'] || '';
        const errorMsg = "⚠️ حساب کاربری شما غیرفعال شده یا مشکلی رخ داده است. لطفاً با پشتیبانی تماس بگیرید.";

        if (isBrowserRequest(userAgent)) {
            const supportLink = TELEGRAM_URL ? `<a href="${TELEGRAM_URL}" class="btn">ارتباط با پشتیبانی تلگرام</a>` : '';
            res.status(500).send(`
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>پشتیبانی</title>
    <style>
        @import url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.0.0/Vazirmatn-font-face.css');
        body { background-color: #110e12; color: #f2f2f2; font-family: 'Vazirmatn', Tahoma, Arial; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; }
        .container { background: #1a171d; padding: 40px; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.08); max-width: 90%; width: 400px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        h2 { color: #d82b57; margin-bottom: 20px; font-size: 24px; }
        p { color: #9aa0a6; line-height: 1.8; font-size: 16px; margin-bottom: 25px; }
        .btn { background: #d82b57; color: white; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; transition: all 0.3s; display: inline-block; }
        .btn:hover { background: #b82247; transform: translateY(-2px); box-shadow: 0 5px 15px rgba(216, 43, 87, 0.4); }
    </style>
</head>
<body>
    <div class="container">
        <h2>⚠️ دسترسی مسدود است</h2>
        <p>${errorMsg}</p>
        ${supportLink}
    </div>
</body>
</html>
            `);
        } else {
            const dummyName = encodeURIComponent(errorMsg);
            // using a standard valid structure: vless://uuid@host:port?type=tcp&security=none#name
            const dummyConfig = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?path=%2F&security=none&encryption=none&type=tcp#" + dummyName + "\n";
            res.status(200).send(Buffer.from(dummyConfig, 'utf-8').toString('base64'));
        }
    }
});

const fetchUrlContent = async function fetchUrlContent(url) {
    try {
        const isHttps = url.startsWith('https://');
        const agent = isHttps ? new https.Agent({ rejectUnauthorized: false })
            : new http.Agent();
        const response = await fetch(url, { agent });
        if (!response.ok) {
            throw new Error(`Failed to fetch URL: ${url}, Status: ${response.status}`);
        }
        return await response.text();
    } catch (error) {
        console.error(`Error fetching URL: ${url}`, error.message);
        throw error;
    }
};

const startServers = () => {
    http.createServer(app).listen(SUB_HTTP_PORT, () => {
        console.log(`HTTP Server is running on port ${SUB_HTTP_PORT}`);
    });

    if (PUBLIC_KEY_PATH && PRIVATE_KEY_PATH &&
        fs.existsSync(PUBLIC_KEY_PATH) && fs.existsSync(PRIVATE_KEY_PATH)) {
        const options = {
            key: fs.readFileSync(PRIVATE_KEY_PATH),
            cert: fs.readFileSync(PUBLIC_KEY_PATH)
        };
        https.createServer(options, app).listen(SUB_HTTPS_PORT, () => {
            console.log(`HTTPS Server is running on port ${SUB_HTTPS_PORT}`);
        });
    } else {
        console.warn('SSL certificates not found. Only HTTP server is running.');
    }
};

startServers();
