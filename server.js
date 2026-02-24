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

// Database pool will be initialized after loading config

const app = express();

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
        let lastConnectionTime = 0;
        let createdTime = Date.now(); // Fallback

        listResult.obj.forEach(inbound => {
            const settings = JSON.parse(inbound.settings);
            const client = settings.clients.find(c => c.email === foundClient.email);
            if (client) {
                inboundsCount++;
            }
        });

        const totalUsageGB = ((trafficData.obj.up + trafficData.obj.down) / 1073741824).toFixed(2);
        const baseLimitGB = inboundsCount > 0 ? ((trafficData.obj.total / inboundsCount) / 1073741824).toFixed(2) : 0;
        const remainingUsageGB = inboundsCount > 0 ? Math.max(0, baseLimitGB - totalUsageGB).toFixed(2) : 0;

        // Try to get total configured days to calculate purchase date (approximate if expiry is set)
        let purchaseDateStr = "نامشخص";
        let lastConnectionStr = "نامشخص";
        let daysText = "نامحدود";
        let statusText = trafficData.obj.enable ? "فعال" : "غیرفعال";
        let isExpired = false;

        // Attempt to find purchase date precisely from the TeleBot DB
        purchaseDateStr = "نامشخص";
        let dbUsername = targetSubId;
        const subIdParts = targetSubId.split('_');
        if (subIdParts.length >= 2) {
            dbUsername = `${subIdParts[0]}_${subIdParts[1]}`; // e.g. 6051224505_a04c
        }

        if (dbPool) {
            try {
                const [rows] = await dbPool.execute('SELECT time_sell FROM invoice WHERE username = ? LIMIT 1', [dbUsername]);
                if (rows.length > 0 && rows[0].time_sell) {
                    const timeSell = rows[0].time_sell;
                    const pDate = new Date(timeSell * 1000);
                    const { jy, jm, jd } = toJalaali(pDate.getFullYear(), pDate.getMonth() + 1, pDate.getDate());
                    purchaseDateStr = `${jy}/${jm < 10 ? '0' + jm : jm}/${jd < 10 ? '0' + jd : jd}`;
                } else {
                    purchaseDateStr = "ثبت نشده در ربات";
                }
            } catch (dbErr) {
                console.error("Database query error for purchase_date:", dbErr.message);
            }
        }

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

        // Fetch explicit client stats if possible (needs Sanaei API ClientStats, but we only have traffics here, 
        // so we can't reliably get last connection without an extra API call. For now, we mock or leave blank).
        // Let's format expiry
        const expiryDate = trafficData.obj.expiryTime > 0 ? new Date(trafficData.obj.expiryTime).toLocaleString('en-US', { month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true }) : "بدون تاریخ اتمام";

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
                // 1. Count how many inbounds this user belongs to
                let inboundsCount = 0;
                listResult.obj.forEach(inbound => {
                    const settings = JSON.parse(inbound.settings);
                    const hasClient = settings.clients.some(c => c.email === foundClient.email);
                    if (hasClient) inboundsCount++;
                });

                if (inboundsCount > 0) {
                    // 2. Calculate actual base limit per inbound
                    const totalUsageGB = ((trafficData.obj.up + trafficData.obj.down) / 1073741824).toFixed(2);
                    const baseLimitGB = ((trafficData.obj.total / inboundsCount) / 1073741824).toFixed(2);

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
                    const dummyConfig = `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:80?type=tcp&security=none#${dummyName}\n`;

                    finalContent = dummyConfig + finalContent;
                }
            } catch (calcError) {
                console.error("Error creating dummy config:", calcError.message);
                // Fallback to normal content if something fails
            }
        }

        res.send(Buffer.from(finalContent, 'utf-8').toString('base64'));
    } catch (error) {
        console.error("Error:", error.message);
        res.status(500).json({ error: error.message });
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
