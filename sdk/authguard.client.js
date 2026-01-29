/**
 * AuthGuard Client SDK v1.0.0
 * The "Digital DNA" Collector for Enterprise Clients.
 */
(function(window) {
    const CONFIG = {
        batchInterval: 4000, // Send telemetry every 4 seconds
        apiEndpoint: null,
        clientId: null,
        userId: null
    };

    // Telemetry Buffer
    let buffer = {
        flights: [], // Keydown -> Keydown time
        dwells: [],  // Keydown -> Keyup time
        mouse_path: [], // Cursor movements
        flags: [] // Bot detection flags
    };

    let lastKeyTime = 0;
    let lastKeyDown = {};

    // --- 1. BOT DETECTION MODULE ---
    function checkBotSignatures() {
        const isHeadless = /HeadlessChrome/.test(window.navigator.userAgent);
        const hasWebDriver = !!navigator.webdriver;
        if (isHeadless || hasWebDriver) buffer.flags.push("AUTOMATION_TOOL_DETECTED");
        if (window.outerWidth === 0 || window.outerHeight === 0) buffer.flags.push("INVALID_SCREEN_DIMENSIONS");
    }

    // --- 2. BEHAVIORAL LISTENERS ---
    function initListeners() {
        // A. Typing Dynamics
        document.addEventListener('keydown', (e) => {
            const now = performance.now();
            if (lastKeyTime > 0) {
                const flight = now - lastKeyTime;
                // Filter out unreasonably long pauses (e.g., user went to get coffee)
                if (flight < 2000) buffer.flights.push(Math.round(flight));
            }
            lastKeyDown[e.code] = now;
            lastKeyTime = now;
        }, { passive: true });

        document.addEventListener('keyup', (e) => {
            const now = performance.now();
            const downTime = lastKeyDown[e.code];
            if (downTime) {
                const dwell = now - downTime;
                buffer.dwells.push(Math.round(dwell));
                delete lastKeyDown[e.code];
            }
        }, { passive: true });

        // B. Mouse Dynamics (Throttled to 20fps to save bandwidth)
        let lastMouseTime = 0;
        document.addEventListener('mousemove', (e) => {
            const now = performance.now();
            if (now - lastMouseTime > 50) { 
                buffer.mouse_path.push({ x: e.clientX, y: e.clientY, t: Math.round(now) });
                lastMouseTime = now;
            }
        }, { passive: true });
    }

    // --- 3. DATA TRANSMISSION ---
    async function sendTelemetry() {
        if (!CONFIG.clientId) return;
        
        // Don't send empty packets
        if (buffer.flights.length === 0 && buffer.mouse_path.length === 0) return;

        const payload = {
            user_uid: CONFIG.userId,
            telemetry: {
                flight_vec: buffer.flights,
                dwell_vec: buffer.dwells,
                // Only send the last 50 mouse points to keep payloads light
                mouse_path: buffer.mouse_path.slice(-50), 
                bot_flags: buffer.flags
            }
        };

        // Clear buffer immediately to avoid duplicate sending
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

            const data = await response.json();
            handleSecurityDecision(data);

        } catch (err) {
            // Fail silently - never break the client's app
            console.warn("AuthGuard telemetry sync failed:", err);
        }
    }

    // --- 4. SECURITY ENFORCEMENT ---
    function handleSecurityDecision(decision) {
        if (decision.decision === "LOCK") {
            showLockScreen(decision.reason);
        } else if (decision.decision === "VERIFY") {
            // Trigger custom event for the host app to handle (e.g., show 2FA)
            const event = new CustomEvent('authguard:verify', { detail: decision });
            window.dispatchEvent(event);
        }
    }

    function showLockScreen(reason) {
        // Create a shadow DOM overlay that is hard to remove via simple scripts
        const overlay = document.createElement('div');
        overlay.id = 'authguard-lock-screen';
        overlay.style.cssText = `
            position: fixed; inset: 0; background: #0f172a; color: white; 
            display: flex; flex-direction: column; align-items: center; justify-content: center; 
            z-index: 2147483647; font-family: system-ui, sans-serif;
        `;
        overlay.innerHTML = `
            <div style="text-align:center; max-width:500px; padding:20px;">
                <h1 style="color:#ef4444; font-size:3rem; margin:0;">🚫 Access Suspended</h1>
                <p style="font-size:1.2rem; margin-top:15px; color:#94a3b8;">
                    Security Anomaly Detected: <strong style="color:white">${reason || 'Unknown Risk'}</strong>
                </p>
                <div style="margin-top:30px; background:#1e293b; padding:20px; border-radius:8px;">
                    <p style="margin:0 0 10px 0;">To unlock your account, request a security code:</p>
                    <button onclick="AuthGuard.requestUnlock()" style="padding:12px 24px; background:#38bdf8; color:#000; border:none; border-radius:6px; cursor:pointer; font-weight:bold; font-size:1rem;">
                        Send Unlock Code
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);
    }

    // --- 5. RECOVERY LOGIC ---
    async function requestUnlock() {
        const email = prompt("Enter your registered email address:");
        if (!email) return;

        try {
            await fetch(`${CONFIG.apiEndpoint}/v1/recover/request`, {
                method: 'POST',
                headers: {'X-API-KEY': CONFIG.clientId, 'Content-Type': 'application/json'},
                body: JSON.stringify({ user_uid: CONFIG.userId, email: email })
            });
            
            const otp = prompt("A 6-digit code has been sent to your email. Enter it here:");
            if (!otp) return;

            const res = await fetch(`${CONFIG.apiEndpoint}/v1/recover/verify`, {
                method: 'POST',
                headers: {'X-API-KEY': CONFIG.clientId, 'Content-Type': 'application/json'},
                body: JSON.stringify({ user_uid: CONFIG.userId, otp: otp })
            });
            
            const data = await res.json();
            if (data.success) {
                alert("Identity Verified. Access Restored.");
                document.getElementById('authguard-lock-screen').remove();
            } else {
                alert("Verification Failed: " + (data.error || "Invalid Code"));
            }
        } catch (e) {
            alert("Recovery Service Unavailable");
        }
    }

    // --- INITIALIZATION ---
    window.AuthGuard = {
        init: (config) => {
            if (!config.clientId || !config.userId) {
                console.error("AuthGuard: Missing clientId or userId");
                return;
            }
            CONFIG.clientId = config.clientId;
            CONFIG.userId = config.userId;
            CONFIG.apiEndpoint = config.endpoint || 'http://localhost:5001';
            
            checkBotSignatures();
            initListeners();
            
            // Start the heartbeat
            setInterval(sendTelemetry, CONFIG.batchInterval);
            console.log("%c 🛡️ AuthGuard Active ", "background: #38bdf8; color: #000; font-weight: bold;");
        },
        requestUnlock: requestUnlock
    };

})(window);