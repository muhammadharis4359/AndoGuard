"""Security test bypass script templates: SSL pinning, root, debug, and emulator detection."""

def generate_ssl_pinning_bypass() -> str:
    """Generate universal Android SSL pinning bypass Frida script."""
    return """// AndoGuard Universal Android SSL Pinning Bypass
Java.perform(function() {
    console.log("[+] Initializing SSL Pinning Bypass...");

    // 1. TrustManagerImpl (Android N+)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] Bypassed TrustManagerImpl.verifyChain for host: " + host);
            return untrustedChain;
        };
    } catch (err) {}

    // 2. OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(str, func) {
            console.log("[+] Bypassed OkHttp3 CertificatePinner.check (Kotlin) for: " + str);
            return;
        };
    } catch (err) {}

    try {
        var CertificatePinner2 = Java.use("okhttp3.CertificatePinner");
        CertificatePinner2.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
            console.log("[+] Bypassed OkHttp3 CertificatePinner.check for: " + str);
            return;
        };
    } catch (err) {}

    // 3. TrustManager checkServerTrusted
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "com.andoguard.OpenTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(a, b, c) {
            console.log("[+] Overriding SSLContext.init with OpenTrustManager");
            SSLContext.init.call(this, a, TrustManagers, c);
        };
    } catch (err) {}

    // 4. WebViewClient onReceivedSslError
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] Bypassed WebViewClient.onReceivedSslError -> handler.proceed()");
            handler.proceed();
        };
    } catch (err) {}

    console.log("[+] SSL Pinning Bypass loaded successfully.");
});
"""


def generate_root_bypass() -> str:
    """Generate universal Android root detection bypass Frida script."""
    return """// AndoGuard Universal Android Root Detection Bypass
Java.perform(function() {
    console.log("[+] Initializing Root Detection Bypass...");

    // 1. Hook File.exists for root binaries and packages
    var File = Java.use("java.io.File");
    var rootPaths = [
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su"
    ];

    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i] || path.endsWith("/su") || path.indexOf("magisk") !== -1) {
                console.log("[+] Bypassed File.exists for root check: " + path);
                return false;
            }
        }
        return this.exists.call(this);
    };

    // 2. Hook Runtime.exec for "su"
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd === "su" || cmd.indexOf("su") !== -1 || cmd.indexOf("which su") !== -1) {
            console.log("[+] Bypassed Runtime.exec for: " + cmd);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec.call(this, cmd);
    };

    // 3. Hook Build.TAGS for "test-keys"
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";

    console.log("[+] Root Detection Bypass loaded successfully.");
});
"""


def generate_debugger_bypass() -> str:
    """Generate debugger detection bypass Frida script."""
    return """// AndoGuard Debugger Detection Bypass
Java.perform(function() {
    console.log("[+] Initializing Debugger Detection Bypass...");

    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Bypassed Debug.isDebuggerConnected() -> false");
        return false;
    };

    Debug.waitingForDebugger.implementation = function() {
        console.log("[+] Bypassed Debug.waitingForDebugger() -> false");
        return false;
    };

    console.log("[+] Debugger Detection Bypass loaded successfully.");
});
"""


def generate_emulator_bypass() -> str:
    """Generate emulator detection bypass Frida script."""
    return """// AndoGuard Emulator Detection Bypass
Java.perform(function() {
    console.log("[+] Initializing Emulator Detection Bypass...");

    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "google/cheetah/cheetah:14/UQ1A.240205.004/11269751:user/release-keys";
    Build.MODEL.value = "Pixel 7 Pro";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "google";
    Build.DEVICE.value = "cheetah";
    Build.PRODUCT.value = "cheetah";
    Build.HARDWARE.value = "cheetah";

    console.log("[+] Emulator Detection Bypass loaded successfully.");
});
"""


def generate_combined_bypass(modules: list[str] | None = None) -> str:
    """Generate unified bypass script combining selected or all security modules."""
    available = {
        "ssl": generate_ssl_pinning_bypass(),
        "root": generate_root_bypass(),
        "debug": generate_debugger_bypass(),
        "emulator": generate_emulator_bypass(),
    }

    selected = modules if modules else list(available.keys())
    parts: list[str] = [
        "// AndoGuard Security Test Bypass Suite",
        f"// Active modules: {', '.join(selected)}",
    ]

    for mod in selected:
        mod_key = mod.lower().strip()
        if mod_key in available:
            parts.append(available[mod_key])

    return "\n\n".join(parts)
