
import type { RuleTier } from './defense/threat-score.js';

export interface OWASPMatch {
    category: string;
    risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    summary: string;
    action: string;
    immediate: boolean;
    confidence?: "LOW" | "MEDIUM" | "HIGH";
    cve?: string[];
    tier: RuleTier;
}

interface OWASPRule {
    category: string;
    risk: OWASPMatch["risk"];
    pattern: RegExp;
    summary: string;
    confidence?: "LOW" | "MEDIUM" | "HIGH";
    cve?: string[];
    immediate?: boolean;
    /** Scoring tier — controls how many points this match contributes */
    tier: RuleTier;
}

export class OWASPScanner {

    private static rules: OWASPRule[] = [

        /* ===================== RCE / CRITICAL ===================== */

        {
            category: "A05:2025-Injection (RCE: Log4Shell)",
            risk: "CRITICAL",
            pattern: /\$\{(?:jndi|lower|upper|env|date|::-):(?:ldap|rmi|dns|http|https):\/\/[^\}]+\}/i,
            summary: "Log4Shell JNDI injection attempt",
            confidence: "HIGH",
            cve: ["CVE-2021-44228", "CVE-2021-45046"],
            tier: "instant",
        },
        {
            category: "A05:2025-Injection (RCE: Spring4Shell)",
            risk: "CRITICAL",
            pattern: /class\.module\.classLoader|classLoader\.resources.*=.*class/i,
            summary: "Spring4Shell class loader manipulation",
            confidence: "MEDIUM",
            cve: ["CVE-2022-22965"],
            tier: "instant",
        },
        {
            category: "A05:2025-Injection (RCE: Apache Text4Shell)",
            risk: "CRITICAL",
            pattern: /\$\{(?:url|dns|script):[^}]+\}/i,
            summary: "Apache Commons Text RCE attempt",
            confidence: "HIGH",
            cve: ["CVE-2022-42889"],
            tier: "instant",
        },
        // REMOVED: React2Shell / Shell2React — matches ALL legitimate RSC flight protocol traffic
        // REMOVED: React Server Actions — matches ALL Next.js server action form submissions
        {
            category: "A05:2025-Injection (Node Module Loader Abuse)",
            risk: "CRITICAL",
            pattern: /process\.mainModule\.require|module\.constructor\._load|require\(process\.env|import\(process\.env/i,
            summary: "Node.js dynamic module loader abuse (post-exploitation)",
            confidence: "HIGH",
            tier: "instant",
        },
        {
            category: "A05:2025-Injection (RCE: Prototype Pollution)",
            risk: "HIGH",
            // Tightened: Only match __proto__ and constructor.prototype when used with
            // assignment operators or in URL query contexts (not in log text or framework internals)
            pattern: /(?:__proto__|constructor\.prototype)\s*(?:=|\[|\.)|Function\s*\(|new\s+Function\s*\(|eval\s*\(/i,
            summary: "Prototype pollution or code execution vector",
            confidence: "MEDIUM",
            tier: "strong",
        },

        /* ===================== INJECTION ===================== */

        {
            category: "A05:2025-Injection (File Upload Exploit)",
            risk: "HIGH",
            pattern: /filename=\".*\.(php|phtml|php3|php4|php5|phps|exe|sh|bat|cmd|pif|scr|js|jar|vbs|vbe|wsf|wsh|msi)\"|Content-Type:\s*application\/x-executable|GIF89a.*<\?php|shell\.php|phpinfo\(\)/i,
            summary: "Malicious file upload attempt with dangerous extension or shell payload",
            confidence: "HIGH",
            tier: "strong",
        },

        {
            category: "A05:2025-Injection (SQLi)",
            risk: "HIGH",
            // Fixed: bare -- and # caused FPs on normal error log text.
            // Now requires SQL context: quotes/parens before comments, whole keywords.
            pattern: /union\s+(all\s+)?select|select\s+[\w*].*\bfrom\b|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep|load_file\s*\(|into\s+outfile|'\s*(OR|AND)\s+'?\d|'\s*--|'\s*#|'\s*\/\*|information_schema|syscolumns|sysobjects/i,
            summary: "SQL injection attempt (classic or time-based)",
            confidence: "HIGH",
            tier: "strong",
        },
        {
            category: "A05:2025-Injection (NoSQL Injection)",
            risk: "HIGH",
            // Tightened: require query-parameter context with bracket notation
            // Old pattern matched $ne/$gt/$lt anywhere — even in legitimate MongoDB URLs
            pattern: /\[\$(?:ne|gt|lt|regex|where)\]|\{\s*"\$(?:ne|gt|lt|regex|where)"/i,
            summary: "NoSQL injection via operator injection",
            confidence: "MEDIUM",
            tier: "strong",
        },
        {
            category: "A05:2025-Injection (XSS)",
            risk: "HIGH",
            pattern: /<script|javascript:|onerror=|onload=|alert\(|document\.cookie|data:text\/html|<svg\s|<iframe|<object|<embed|<base\s|onmouseover=/i,
            summary: "Cross-site scripting payload detected",
            confidence: "HIGH",
            tier: "strong",
        },
        {
            category: "A05:2025-Injection (OS Command)",
            risk: "HIGH",
            // Require shell operators followed by whitespace/path context + whole-word command names
            // Avoids FP like "compatible; Bytespider; bytedance.com" matching ; + nc
            pattern: /(;|\|\||&&|`|\$\()\s*(\/[\w\/]+\/|sudo\s+|env\s+)?\b(sh|bash|curl|wget|nc|ncat|python\d?|perl|php|ruby|rm|cat|ls|whoami|ifconfig|netstat|nmap|passwd|chmod|chown|useradd|mkfifo|telnet|socat)\b/i,
            summary: "OS command injection attempt",
            confidence: "HIGH",
            tier: "strong",
        },
        {
            category: "A05:2025-Injection (SSTI)",
            risk: "HIGH",
            // Tightened: require actual template injection keywords, not just ${...}
            // Old pattern matched JavaScript template literals like ${variable}
            pattern: /\{\{.*(__class__|config|self|globals|os|subprocess).*}}|<%.*%>|\$\{(?:__class__|import|os|subprocess|eval|exec|open)\b/i,
            summary: "Server-Side Template Injection attempt",
            confidence: "MEDIUM",
            tier: "strong",
        },

        /* ===================== ACCESS CONTROL / SSRF ===================== */

        {
            category: "A01:2025-Broken Access Control (SSRF)",
            risk: "HIGH",
            // Tightened: Only match cloud metadata + dangerous protocols
            // REMOVED localhost/127.0.0.1 — too many FPs from log text itself
            pattern: /169\.254\.169\.254|metadata\.google\.internal|instance-data\.amazonaws\.com|file:\/\/|gopher:\/\/|tftp:\/\/|expect:\/\/|php:\/\/filter/i,
            summary: "SSRF or protocol handler bypass attempt targeting internal or cloud metadata services",
            confidence: "HIGH",
            tier: "strong",
        },
        {
            category: "A01:2025-Broken Access Control (Path Traversal)",
            risk: "HIGH",
            pattern: /\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/proc\/self|win\.ini|Windows\\System32|etc\/shadow/i,
            summary: "Path traversal or local file inclusion attempt",
            confidence: "HIGH",
            tier: "strong",
        },
        {
            category: "A01:2025-Broken Access Control (Sensitive Files)",
            risk: "MEDIUM",
            // Tightened: require HTTP method context (GET/POST) or path prefix (/)
            // to avoid matching when our OWN log text mentions .env or .git
            pattern: /(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+[^\s]*(?:\.env|\.git\/|id_rsa|\.dockerconfigjson|secrets\.yml|\.kube\/config)/i,
            summary: "Attempt to access secrets or configuration files",
            confidence: "MEDIUM",
            tier: "signal",
        },
        // DEMOTED: Next.js internal probing — this is NORMAL Next.js traffic
        {
            category: "A01:2025-Broken Access Control (Next.js Probing)",
            risk: "LOW",
            pattern: /_next\/static|_next\/data|\/_next\/image|\/_next\/webpack-hmr/i,
            summary: "Next.js internal static or data request",
            confidence: "LOW",
            tier: "noise",
        },

        /* ===================== DESERIALIZATION / XXE ===================== */

        {
            category: "A08:2025-Insecure Deserialization / XXE",
            risk: "HIGH",
            pattern: /<!DOCTYPE|<!ENTITY.*SYSTEM|ACED0005|rO0AB|\[serialization\]|JSON\.parse\(.*\.toString\(\)|node-serialize/i,
            summary: "Insecure deserialization, XXE, or Node.js serialization payload",
            confidence: "HIGH",
            tier: "strong",
        },

        /* ===================== AUTH / API ===================== */

        {
            category: "A07:2025-Authentication Failures (JWT)",
            risk: "HIGH",
            pattern: /"alg"\s*:\s*"none"|"kid"\s*:\s*"\.\.\/|jwt-secret/i,
            // REMOVED: eyJhbGc pattern — every legitimate JWT in logs matches this
            summary: "JWT manipulation, none-algorithm, or path traversal in kid",
            confidence: "MEDIUM",
            tier: "strong",
        },
        {
            category: "A04:2025-Insecure Design (GraphQL)",
            risk: "LOW",
            pattern: /__schema|__type|graphql-playground|introspection/i,
            summary: "GraphQL introspection or schema probing",
            confidence: "LOW",
            tier: "noise",
        },

        /* ===================== MISCONFIG / INFO LEAK ===================== */

        // DEMOTED TO NOISE: Exception leakage is YOUR server's errors, not incoming attacks
        {
            category: "A10:2025-Exception Leakage",
            risk: "LOW",
            pattern: /StackTrace|NullPointerException|Fatal error|Traceback|ERR_HTTP_INVALID_CHAR|ERR_INVALID_URL|P2002|PrismaClientKnownRequestError/i,
            summary: "Application exception details or Prisma error leaked",
            confidence: "LOW",
            tier: "noise",
        },

        /* ===================== SUPPLY CHAIN ===================== */
        // REMOVED: The old rule matched OUR OWN package.json, Dockerfile, etc. in logs.
        // Only keep if someone is literally trying to download these via HTTP.
        {
            category: "A03:2025-Software Supply Chain",
            risk: "MEDIUM",
            // Tightened: require HTTP method context
            pattern: /(?:GET|POST)\s+[^\s]*(?:\.npmrc|\.github\/workflows|docker-compose\.ya?ml)/i,
            summary: "CI/CD or dependency artifact access attempt",
            confidence: "MEDIUM",
            tier: "signal",
        },

        /* ===================== SCANNER FINGERPRINTS ===================== */

        {
            category: "A09:2025-Security Logging (Scanner Fingerprint)",
            risk: "HIGH",
            pattern: /(?:Nikto|sqlmap|Nmap|ZGrab|Masscan|WPScan|Acunetix|Nessus|OpenVAS|Burp|dirbuster|gobuster|feroxbuster|ffuf|nuclei|httpx|subfinder|amass)\b/i,
            summary: "Known vulnerability scanner or recon tool detected",
            confidence: "HIGH",
            immediate: true,
            tier: "instant",
        },
        // DEMOTED: Empty User-Agent is extremely common for APIs, health checks, monitoring
        {
            category: "A09:2025-Security Logging (Suspicious User-Agent)",
            risk: "LOW",
            pattern: /^[^"]*"[^"]*"\s+\d+\s+\d+\s+"[^"]*"\s+"(-|)"\s*$/i,
            summary: "Request with empty or missing User-Agent",
            confidence: "LOW",
            tier: "noise",
        },

        /* ===================== WORDPRESS SPECIFIC ===================== */

        {
            category: "A01:2025-Broken Access Control (WordPress)",
            risk: "HIGH",
            pattern: /wp-login\.php|wp-admin\/admin-ajax\.php|wp-content\/uploads\/.*\.php|wp-includes\/.*\.php\?|\/wp-json\/wp\/v2\/users/i,
            summary: "WordPress login brute-force or user enumeration",
            confidence: "HIGH",
            tier: "strong",
        },
        {
            category: "A01:2025-Broken Access Control (WordPress: XMLRPC)",
            risk: "MEDIUM",
            pattern: /xmlrpc\.php/i,
            summary: "WordPress XML-RPC interface access (Potential brute-force or pingback abuse)",
            confidence: "MEDIUM",
            tier: "signal",
        },
        {
            category: "A06:2025-Vulnerable Components (WordPress Plugins)",
            risk: "HIGH",
            pattern: /wp-content\/plugins\/(revslider|timthumb|akismet|contact-form-7|elementor|wpforms|woocommerce).*\.(php|txt|zip|bak|sql)/i,
            summary: "Targeting known vulnerable WordPress plugin paths",
            confidence: "MEDIUM",
            tier: "strong",
        },

        /* ===================== WEBSHELL & BACKDOOR ===================== */

        {
            category: "A05:2025-Injection (Webshell)",
            risk: "CRITICAL",
            pattern: /c99|r57|b374k|wso\.php|FilesMan|WSO\s|alfa-shell|webshell|phpspy|phpremoteview|mini_shell|p0wny|antak/i,
            summary: "Known webshell or backdoor access detected",
            confidence: "HIGH",
            tier: "instant",
        },
        {
            category: "A05:2025-Injection (PHP Eval/Assert)",
            risk: "HIGH",
            pattern: /assert\s*\(|eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|base64_decode\s*\(\s*\$_|system\s*\(\s*\$_|passthru\s*\(|exec\s*\(\s*\$_/i,
            summary: "PHP code execution via eval/assert/system with user input",
            confidence: "HIGH",
            tier: "instant",
        },

        /* ===================== API ABUSE ===================== */

        {
            category: "A02:2025-Cryptographic Failures (API Key Leak)",
            risk: "HIGH",
            pattern: /(?:(?:sk|pk)[-_](?:test|live|prod)[-_][a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-_]{20,}|AKIA[A-Z0-9]{16})/i,
            summary: "Potential API key or secret token in request (Stripe, GitHub, GitLab, AWS)",
            confidence: "MEDIUM",
            tier: "signal",
        },
        {
            category: "A04:2025-Insecure Design (Mass Assignment)",
            risk: "MEDIUM",
            pattern: /\b(isAdmin|is_admin|role|permission|privilege|admin)\b\s*[=:]\s*(true|1|"admin"|"root")/i,
            summary: "Potential mass assignment or privilege escalation attempt",
            confidence: "MEDIUM",
            tier: "signal",
        },

        /* ===================== CRYPTO / MINING ===================== */

        {
            category: "A05:2025-Injection (Cryptominer)",
            risk: "CRITICAL",
            pattern: /stratum\+tcp|xmrig|coinhive|cryptonight|monero|coinminer|kinsing|TeamTNT/i,
            summary: "Cryptomining payload or known mining botnet signature",
            confidence: "HIGH",
            tier: "instant",
        },

        /* ===================== CRLF / HEADER INJECTION ===================== */

        // DEMOTED: %0d%0a appears in many legitimate URL-encoded parameters
        {
            category: "A05:2025-Injection (CRLF / Header Injection)",
            risk: "MEDIUM",
            // Tightened: require actual header injection payloads, not just bare CRLF encoding
            pattern: /(?:%0d%0a|\\r\\n)\s*(?:Set-Cookie:|Location:|HTTP\/|Content-Type:)/i,
            summary: "CRLF injection with HTTP header manipulation attempt",
            confidence: "MEDIUM",
            tier: "signal",
        },

        /* ===================== OPEN REDIRECT ===================== */

        {
            category: "A01:2025-Broken Access Control (Open Redirect)",
            risk: "MEDIUM",
            pattern: /[?&](redirect|url|next|return|goto|dest|destination|rurl|link|target)=https?:\/\//i,
            summary: "Potential open redirect via URL parameter",
            confidence: "MEDIUM",
            tier: "signal",
        }
    ];

    /* ===================== SCANNER ===================== */

    public static scan(rawLine: string): OWASPMatch[] {
        if (!rawLine) return [];

        // Fast Path: If the line doesn't contain any traditional exploit delivery characters, skip regex.
        // This avoids overhead for 90%+ of normal log lines (e.g. standard static assets or clean GETs).
        if (!/[{}$'\"<>;|&`\(\)\[\]]/.test(rawLine)) {
            return [];
        }

        try {
            // Normalize: URL Decoding + Null-byte removal
            const line = decodeURIComponent(rawLine.toLowerCase().replace(/\0/g, ""));
            const matches: OWASPMatch[] = [];

            for (const rule of this.rules) {
                if (rule.pattern.test(line)) {
                    matches.push({
                        category: rule.category,
                        risk: rule.risk,
                        summary: rule.summary,
                        action: "Immediate mitigation recommended (" + rule.category + ")",
                        immediate: rule.immediate ?? (rule.risk === "CRITICAL"),
                        confidence: rule.confidence,
                        cve: rule.cve,
                        tier: rule.tier,
                    });
                }
            }

            return matches;
        } catch (e) {
            // If decode fails (e.g. malformed percent encoding), fallback to raw line normalization
            const line = rawLine.toLowerCase().replace(/\0/g, "");
            const matches: OWASPMatch[] = [];
            for (const rule of this.rules) {
                if (rule.pattern.test(line)) {
                    matches.push({
                        category: rule.category,
                        risk: rule.risk,
                        summary: rule.summary,
                        action: "Immediate mitigation recommended (" + rule.category + ")",
                        immediate: rule.immediate ?? (rule.risk === "CRITICAL"),
                        confidence: rule.confidence,
                        cve: rule.cve,
                        tier: rule.tier,
                    });
                }
            }
            return matches;
        }
    }
}
