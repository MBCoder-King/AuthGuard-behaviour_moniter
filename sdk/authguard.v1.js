/**
 * AuthGuard Enterprise SDK v2.0 (Firebase + Fingerprinting)
 */
(function(window) {
    'use strict';   
    const CONFIG = {
        batchInterval: 4000,
        apiEndpoint: 'http://localhost:5001',
        clientId: null,
        userId: null
    };

    let buffer = { flights: [], dwells: [], mouse_path: [], flags: [] };
    let lastKeyTime = 0;
    let lockScreenActive = false;

    // --- NEW FEATURE: DEVICE FINGERPRINTING ---
    function getDeviceFingerprint() {
        return {
            userAgent: navigator.userAgent,
            screenRes: `${window.screen.width}x${window.screen.height}`,
            colorDepth: window.screen.colorDepth,
            cores: navigator.hardwareConcurrency || 'unknown',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
        };
    }

    // --- BOT DETECTION ---
    function performEnvironmentChecks() {
        if (/HeadlessChrome|PhantomJS|Selenium/.test(navigator.userAgent)) {
            buffer.flags.push("AUTOMATION_TOOL_DETECTED");
        }
        if (window.outerWidth === 0 && window.outerHeight === 0) {
            buffer.flags.push("HEADLESS_GEOMETRY");
        }
    }

    // --- TELEMETRY COLLECTION ---
    function initListeners() {
        document.addEventListener('keydown', (e) => {
            if (lockScreenActive) return;
            const now = performance.now();
            if (lastKeyTime > 0) {
                const flight = now - lastKeyTime;
                if (flight < 2000) buffer.flights.push(Math.round(flight));
            }
            lastKeyTime = now;
        }, { passive: true });

        let lastMouseTime = 0;
        document.addEventListener('mousemove', (e) => {
            if (lockScreenActive) return;
            const now = performance.now();
            if (now - lastMouseTime > 50) { 
                buffer.mouse_path.push({ x: e.clientX, y: e.clientY, t: Math.round(now) });
                lastMouseTime = now;
            }
        }, { passive: true });
    }

    // --- SYNC ---
    async function syncTelemetry() {
        if (!CONFIG.clientId || lockScreenActive) return;
        
        if (buffer.flights.length === 0 && buffer.mouse_path.length === 0) return;

        const payload = {
            user_uid: CONFIG.userId,
            fingerprint: getDeviceFingerprint(), // Send Fingerprint
            telemetry: {
                flight_vec: buffer.flights,
                mouse_path: buffer.mouse_path.slice(-50),
                bot_flags: buffer.flags
            }
        };

        buffer = { flights: [], dwells: [], mouse_path: [], flags: [] };

        try {
            const response = await fetch(`${CONFIG.apiEndpoint}/v1/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-KEY': CONFIG.clientId
                },
                body: JSON.stringify(payload),
                keepalive: true
            });

            if (response.status === 403) {
                handleDecision({ decision: "LOCK", reason: "Access Denied by Server" });
            } else {
                const data = await response.json();
                handleDecision(data);
            }
        } catch (err) {
            console.warn("[AuthGuard] Sync failed", err);
        }
    }

    function handleDecision(data) {
        if (data.decision === "LOCK") {
            lockScreenActive = true;
            renderLockScreen(data.reasons ? data.reasons.join(", ") : "High Risk Detected");
        }
    }

    // --- LOCK UI ---
    function renderLockScreen(reason) {
        if (document.getElementById('ag-lock-root')) return;
        const host = document.createElement('div');
        host.id = 'ag-lock-root';
        document.body.appendChild(host);
        const shadow = host.attachShadow({ mode: 'closed' });
        
        shadow.innerHTML = `
            <div style="position:fixed; inset:0; background:#0f172a; color:white; z-index:99999; display:flex; flex-direction:column; align-items:center; justify-content:center; font-family:sans-serif;">
                <h1 style="color:#ef4444; font-size:3rem; margin-bottom:10px;">🚫 Security Lock</h1>
                <p style="color:#cbd5e1; font-size:1.2rem;">${reason}</p>
                <button onclick="alert('Contact Admin to unlock')" style="margin-top:20px; padding:10px 20px; background:#38bdf8; border:none; border-radius:5px; cursor:pointer; font-weight:bold;">Contact Support</button>
            </div>
        `;
    }

    window.AuthGuard = {
        init: (cfg) => {
            Object.assign(CONFIG, cfg);
            performEnvironmentChecks();
            initListeners();
            setInterval(syncTelemetry, CONFIG.batchInterval);
        }
    };
})(window);