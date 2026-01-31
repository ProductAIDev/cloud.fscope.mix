// cloudfront-js-2.0 function

function handler(event) {
    var req = event.request;
    var uri = req.uri;

    // --- Safe host extraction ---
    var host = "";
    if (req.headers.host && req.headers.host.value) {
        host = req.headers.host.value;
    }

    // --- Safe UA extraction ---
    var ua = "";
    if (req.headers["user-agent"] && req.headers["user-agent"].value) {
        ua = req.headers["user-agent"].value.toLowerCase();
    }

    // --- Safe IP extraction ---
    var ip = req.clientIp || "";

    // --- 1. Block WordPress attack paths ---
    var lowerUri = uri.toLowerCase();

    // Normalize multiple slashes
    var normalized = uri.toLowerCase().replace(/\/+/g, "/");

    // 1. ALLOW ONLY "/" and "/index.html"
    var allowed = false;
    if (normalized === "/" || normalized === "/index.html") {
        allowed = true;
    }
    if (!allowed) {
        return {
            statusCode: 403,
            statusDescription: "Forbidden",
            headers: {
                "content-type": {
                    value: "text/plain"
                }
            },
            body: "Forbidden"
        };
    }

    if (normalized.indexOf("/wordpress") === 0) {
        return {
            statusCode: 403,
            statusDescription: "Forbidden",
            headers: { "content-type": { value: "text/plain" } },
            body: "Forbidden"
        };
    }

    // Block WordPress specific paths (without wordpress)
    if (
        normalized === "/wp-admin" ||
        normalized.indexOf("/wp-admin/") === 0 ||
        normalized === "/wp-login.php" ||
        normalized === "/xmlrpc.php"
    ) {
        return {
            statusCode: 403,
            statusDescription: "Forbidden",
            headers: { "content-type": { value: "text/plain" } },
            body: "Forbidden"
        };
    }

    // --- 2. Block suspicious user agents ---
    if (
        ua.indexOf("curl") >= 0 ||
        ua.indexOf("python") >= 0 ||
        ua.indexOf("wp-admin") >= 0 ||
        ua.indexOf("wget") >= 0 ||
        ua.indexOf("bot") >= 0 ||
        ua.indexOf("scanner") >= 0
    ) {
        return {
            statusCode: 403,
            statusDescription: "Forbidden",
            headers: { "content-type": { value: "text/plain" } },
            body: "Blocked"
        };
    }

    // --- 3. Block known bad IP ranges ---
    if (
        ip.indexOf("104.23.") === 0 ||
        ip.indexOf("104.24.") === 0 ||
        ip.indexOf("2a06:98c0:") === 0
    ) {
        return {
            statusCode: 403,
            statusDescription: "Forbidden",
            headers: { "content-type": { value: "text/plain" } },
            body: "Blocked"
        };
    }

    // --- 4. robots.txt ---
    if (uri === "/robots.txt") {
        return {
            statusCode: 200,
            statusDescription: "OK",
            headers: { "content-type": { value: "text/plain" } },
            body: "User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-login.php\nDisallow: /xmlrpc.php"
        };
    }

    // --- 5. Redirect root domain → www ---
    if (host === "productai.dev") {
        return {
            statusCode: 301,
            statusDescription: "Moved Permanently",
            headers: {
                location: { value: "https://www.productai.dev" + uri }
            }
        };
    }

    // --- 6. Rewrite "/" → "/index.html" ---
    if (uri === "/") {
        req.uri = "/index.html";
    }

    return req;
}

