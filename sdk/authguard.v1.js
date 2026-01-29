/**
 * AuthGuard Enterprise SDK v1.0.0
 * The "Digital DNA" Behavioral Biometrics Collector.
 * * Usage:
 * <script src="authguard.v1.js"></script>
 * <script>
 * AuthGuard.init({
 * clientId: "ag_live_YOUR_KEY",
 * userId: "unique_user_id",
 * endpoint: "http://localhost:5001"
 * });
 * </script>
 */

(function(window) {
    'use strict';

    const CONFIG = {
        batchInterval: 4000, // Send data every 4s
        apiEndpoint: 'http://localhost:5001',
        clientId: null,
        userId: null,
        debug: false
    };

    // Telemetry Buffer
    let buffer = {
        flights: [],     // Typing rhythm (Keydown -> Keydown)
        dwells: [],      // Key press duration (Keydown -> Keyup)
        mouse_path: [],  // Cursor vectors
        scrolls: [],     // Scroll events
        flags: []        // Bot detection signals
    };

    let lastKeyTime = 0;
    let lastKeyDown = {};
    let lockScreenActive = false;

    // --- 1. BOT & ENVIRONMENT CHECKS ---
    function performEnvironmentChecks() {
        const ua = window.navigator.userAgent;
        if (/HeadlessChrome|PhantomJS|Selenium/.test(ua)) {
            buffer.flags.push("BOT_USER_AGENT");
        }
        if (window.outerWidth === 0 && window.outerHeight === 0) {
            buffer.flags.push("HEADLESS_GEOMETRY");
        }
        if (navigator.webdriver) {
            buffer.flags.push("WEBDRIVER_DETECTED");
        }
    }

    // --- 2. BEHAVIORAL LISTENERS ---
    function initListeners() {
        // A. Typing Dynamics
        document.addEventListener('keydown', (e) => {
            if (lockScreenActive) return;
            const now = performance.now();
            
            // Flight Time
            if (lastKeyTime > 0) {
                const flight = now - lastKeyTime;
                if (flight < 2000) buffer.flights.push(Math.round(flight));
            }
            
            lastKeyDown[e.code] = now;
            lastKeyTime = now;
        }, { passive: true });

        document.addEventListener('keyup', (e) => {
            if (lockScreenActive) return;
            const now = performance.now();
            const downTime = lastKeyDown[e.code];
            if (downTime) {
                const dwell = now - downTime;
                buffer.dwells.push(Math.round(dwell));
                delete lastKeyDown[e.code];
            }
        }, { passive: true });

        // B. Mouse Dynamics (Throttled 20fps)
        let lastMouseTime = 0;
        document.addEventListener('mousemove', (e) => {
            if (lockScreenActive) return;
            const now = performance.now();
            if (now - lastMouseTime > 50) { 
                buffer.mouse_path.push({ 
                    x: e.clientX, 
                    y: e.clientY, 
                    t: Math.round(now) 
                });
                lastMouseTime = now;
            }
        }, { passive: true });

        // C. Scroll
        document.addEventListener('scroll', () => {
            buffer.scrolls.push(performance.now());
        }, { passive: true });
    }

    // --- 3. NETWORK TRANSMISSION ---
    async function syncTelemetry() {
        if (!CONFIG.clientId) return;
        
        // Skip if buffer empty (save bandwidth)
        if (buffer.flights.length === 0 && buffer.mouse_path.length === 0) return;

        const payload = {
            user_uid: CONFIG.userId,
            telemetry: {
                flight_vec: buffer.flights,
                dwell_vec: buffer.dwells,
                mouse_path: buffer.mouse_path.slice(-50), // Optimization: Send last 50 points
                bot_flags: buffer.flags
            }
        };

        // Flush buffer immediately
        buffer = { flights: [], dwells: [], mouse_path: [], scrolls: [], flags: [] };

        try {
            const response = await fetch(`${CONFIG.apiEndpoint}/v1/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-KEY': CONFIG.clientId
                },
                body: JSON.stringify(payload),
                keepalive: true // Critical: Ensures request survives page navigation
            });

            if (response.status === 403) {
                // Immediate Lockout if forbidden
                handleDecision({ decision: "LOCK", reason: "Access Denied by Server" });
            } else {
                const data = await response.json();
                handleDecision(data);
            }
        } catch (err) {
            if (CONFIG.debug) console.warn("[AuthGuard] Sync failed", err);
        }
    }

    // --- 4. DECISION ENFORCEMENT ---
    function handleDecision(data) {
        if (data.decision === "LOCK") {
            lockScreenActive = true;
            renderLockScreen(data.reason);
        } else if (data.decision === "VERIFY") {
            // Dispatch event for client app to handle (e.g., trigger 2FA)
            window.dispatchEvent(new CustomEvent('authguard:verify', { detail: data }));
        }
    }

    // --- 5. SECURE LOCK UI (SHADOW DOM) ---
    function renderLockScreen(reason) {
        if (document.getElementById('ag-lock-root')) return;

        const host = document.createElement('div');
        host.id = 'ag-lock-root';
        document.body.appendChild(host);

        const shadow = host.attachShadow({ mode: 'closed' }); // 'closed' prevents JS access from outside

        const style = document.createElement('style');
        style.textContent = `
            :host { all: initial; }
            .overlay {
                position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
                background: #0f172a; color: white; z-index: 2147483647;
                display: flex; flex-direction: column; align-items: center; justify-content: center;
                font-family: system-ui, -apple-system, sans-serif;
            }
            h1 { color: #ef4444; margin: 0 0 20px 0; font-size: 2.5rem; }
            p { color: #94a3b8; font-size: 1.1rem; max-width: 400px; text-align: center; line-height: 1.5; }
            .btn {
                margin-top: 30px; padding: 12px 24px; background: #38bdf8; color: #000;
                border: none; border-radius: 6px; font-weight: bold; cursor: pointer;
                font-size: 1rem; transition: transform 0.1s;
            }
            .btn:active { transform: scale(0.98); }
        `;

        const container = document.createElement('div');
        container.className = 'overlay';
        container.innerHTML = `
            <h1>🚫 Identity Locked</h1>
            <p>We detected anomalous behavior patterns inconsistent with your verified profile.</p>
            <p style="font-size: 0.9rem; margin-top: 10px; color: #64748b;">Reason: ${reason || 'High Behavioral Risk'}</p>
            <button class="btn" id="unlockBtn">Verify Identity via Email</button>
        `;

        shadow.appendChild(style);
        shadow.appendChild(container);

        // Bind Unlock Logic
        shadow.getElementById('unlockBtn').onclick = () => requestRecovery();
    }

    // --- 6. RECOVERY FLOW ---
    async function requestRecovery() {
        const email = prompt("Enter your registered email to receive an Unlock Code:");
        if (!email) return;

        try {
            await fetch(`${CONFIG.apiEndpoint}/v1/recover/request`, {
                method: 'POST',
                headers: {'X-API-KEY': CONFIG.clientId, 'Content-Type': 'application/json'},
                body: JSON.stringify({ user_uid: CONFIG.userId, email: email })
            });

            const otp = prompt("Enter the 6-digit code sent to your email:");
            if (!otp) return;

            const res = await fetch(`${CONFIG.apiEndpoint}/v1/recover/verify`, {
                method: 'POST',
                headers: {'X-API-KEY': CONFIG.clientId, 'Content-Type': 'application/json'},
                body: JSON.stringify({ user_uid: CONFIG.userId, otp: otp })
            });

            const data = await res.json();
            if (data.success) {
                alert("Identity Verified. Access Restored.");
                document.getElementById('ag-lock-root').remove();
                lockScreenActive = false;
            } else {
                alert("Verification Failed: " + (data.error || "Invalid Code"));
            }
        } catch (e) {
            console.error(e);
            alert("Recovery Service Error");
        }
    }

    // --- PUBLIC API ---
    window.AuthGuard = {
        init: (cfg) => {
            if (!cfg.clientId || !cfg.userId) {
                console.error("AuthGuard: Missing config (clientId/userId)");
                return;
            }
            Object.assign(CONFIG, cfg);
            performEnvironmentChecks();
            initListeners();
            setInterval(syncTelemetry, CONFIG.batchInterval);
            if(CONFIG.debug) console.log("🛡️ AuthGuard Protection Active");
        }
    };

})(window);