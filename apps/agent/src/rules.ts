
export interface OWASPMatch {
    category: string;
    risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    summary: string;
    action: string;
    immediate: boolean;
    confidence?: "LOW" | "MEDIUM" | "HIGH";
    cve?: string[];
}

interface OWASPRule {
    category: string;
    risk: OWASPMatch["risk"];
    pattern: RegExp;
    summary: string;
    confidence?: "LOW" | "MEDIUM" | "HIGH";
    cve?: string[];
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
            cve: ["CVE-2021-44228", "CVE-2021-45046"]
        },
        {
            category: "A05:2025-Injection (RCE: Spring4Shell)",
            risk: "CRITICAL",
            pattern: /class\.module\.classLoader|classLoader\.resources.*=.*class/i,
            summary: "Spring4Shell class loader manipulation",
            confidence: "MEDIUM",
            cve: ["CVE-2022-22965"]
        },
        {
            category: "A05:2025-Injection (RCE: Apache Text4Shell)",
            risk: "CRITICAL",
            pattern: /\$\{(?:url|dns|script):[^}]+\}/i,
            summary: "Apache Commons Text RCE attempt",
            confidence: "HIGH",
            cve: ["CVE-2022-42889"]
        },
        {
            category: "A05:2025-Injection (RCE: React2Shell / Shell2React)",
            risk: "CRITICAL",
            pattern: /clientReference|__reactServerComponent__|rsc-action|flight-protocol/i,
            summary: "React2Shell unauthenticated RCE attempt targeting RSC Flight protocol",
            confidence: "HIGH",
            cve: ["CVE-2025-55182", "CVE-2025-66478"]
        },
        {
            category: "A05:2025-Injection (RCE: React Server Actions)",
            risk: "CRITICAL",
            pattern: /use\s+server|serverAction|__NEXT_ACTION__|next-action/i,
            summary: "React Server Actions abuse or manipulation attempt",
            confidence: "MEDIUM"
        },
        {
            category: "A05:2025-Injection (Node Module Loader Abuse)",
            risk: "CRITICAL",
            pattern: /process\.mainModule\.require|module\.constructor\._load|require\(process\.env|import\(process\.env/i,
            summary: "Node.js dynamic module loader abuse (post-exploitation)",
            confidence: "HIGH"
        },
        {
            category: "A05:2025-Injection (RCE: React / Next.js)",
            risk: "CRITICAL",
            pattern: /__proto__|constructor\.prototype|__reactServerComponent__|getServerSideProps.*process\.env|Function\(|new\s+Function\(|eval\(/i,
            summary: "Prototype pollution or React/Next.js server-side RCE vector",
            confidence: "MEDIUM"
        },

        /* ===================== INJECTION ===================== */

        {
            category: "A05:2025-Injection (File Upload Exploit)",
            risk: "HIGH",
            pattern: /filename=\".*\.(php|phtml|php3|php4|php5|phps|exe|sh|bat|cmd|pif|scr|js|jar|vbs|vbe|wsf|wsh|msi)\"|Content-Type:\s*application\/x-executable|GIF89a.*<\?php|shell\.php|phpinfo\(\)/i,
            summary: "Malicious file upload attempt with dangerous extension or shell payload",
            confidence: "HIGH"
        },

        {
            category: "A05:2025-Injection (SQLi)",
            risk: "HIGH",
            // Fixed: bare -- and # caused FPs on normal error log text.
            // Now requires SQL context: quotes/parens before comments, whole keywords.
            pattern: /union\s+(all\s+)?select|select\s+[\w*].*\bfrom\b|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep|load_file\s*\(|into\s+outfile|'\s*(OR|AND)\s+'?\d|'\s*--|'\s*#|'\s*\/\*|;\s*--|information_schema|syscolumns|sysobjects/i,
            summary: "SQL injection attempt (classic or time-based)",
            confidence: "HIGH"
        },
        {
            category: "A05:2025-Injection (NoSQL / Prototype Pollution)",
            risk: "HIGH",
            pattern: /\$(ne|gt|lt|regex|where)|__proto__|constructor\.prototype/i,
            summary: "NoSQL injection or JavaScript prototype pollution",
            confidence: "MEDIUM"
        },
        {
            category: "A05:2025-Injection (XSS)",
            risk: "HIGH",
            pattern: /<script|javascript:|onerror=|onload=|alert\(|document\.cookie|data:text\/html|<svg|<iframe|<object|<embed|<base|onmouseover=/i,
            summary: "Cross-site scripting payload detected",
            confidence: "HIGH"
        },
        {
            category: "A05:2025-Injection (OS Command)",
            risk: "HIGH",
            // Require shell operators followed by whitespace/path context + whole-word command names
            // Avoids FP like "compatible; Bytespider; bytedance.com" matching ; + nc
            pattern: /(;|\|\||&&|`|\$\()\s*(\/[\w\/]+\/|sudo\s+|env\s+)?\b(sh|bash|curl|wget|nc|ncat|python\d?|perl|php|ruby|rm|cat|ls|whoami|ifconfig|netstat|nmap|passwd|chmod|chown|useradd|mkfifo|telnet|socat)\b/i,
            summary: "OS command injection attempt",
            confidence: "HIGH"
        },
        {
            category: "A05:2025-Injection (SSTI)",
            risk: "HIGH",
            pattern: /\{\{.*(__class__|config|self|globals|os|subprocess).*}}|<%.*%>|\${.*}/i,
            summary: "Server-Side Template Injection attempt",
            confidence: "MEDIUM"
        },

        /* ===================== ACCESS CONTROL / SSRF ===================== */

        {
            category: "A01:2025-Broken Access Control (SSRF)",
            risk: "HIGH",
            pattern: /169\.254\.169\.254|metadata\.google\.internal|instance-data\.amazonaws\.com|localhost|127\.0\.0\.1|file:\/\/|gopher:\/\/|data:\/\/|tftp:\/\/|expect:\/\/|php:\/\/filter/i,
            summary: "SSRF or protocol handler bypass attempt targeting internal or cloud metadata services",
            confidence: "HIGH"
        },
        {
            category: "A01:2025-Broken Access Control (Path Traversal)",
            risk: "HIGH",
            pattern: /\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/proc\/self|win\.ini|Windows\\System32|etc\/shadow/i,
            summary: "Path traversal or local file inclusion attempt",
            confidence: "HIGH"
        },
        {
            category: "A01:2025-Broken Access Control (Sensitive Files)",
            risk: "HIGH",
            pattern: /\.env|\.git\/|id_rsa|\.dockerconfigjson|config\.ya?ml|secrets\.yml|\.kube\/config|prisma\/schema\.prisma/i,
            summary: "Attempt to access secrets, configuration, or Prisma schema",
            confidence: "HIGH"
        },
        {
            category: "A01:2025-Broken Access Control (Next.js Probing)",
            risk: "MEDIUM",
            pattern: /_next\/static|_next\/data|\/_next\/image|\/_next\/webpack-hmr/i,
            summary: "Probing of Next.js internal static or data directories",
            confidence: "MEDIUM"
        },

        /* ===================== DESERIALIZATION / XXE ===================== */

        {
            category: "A08:2025-Insecure Deserialization / XXE",
            risk: "HIGH",
            pattern: /<!DOCTYPE|<!ENTITY.*SYSTEM|ACED0005|rO0AB|\[serialization\]|JSON\.parse\(.*\.toString\(\)|node-serialize/i,
            summary: "Insecure deserialization, XXE, or Node.js serialization payload",
            confidence: "HIGH"
        },

        /* ===================== AUTH / API ===================== */

        {
            category: "A07:2025-Authentication Failures (JWT)",
            risk: "HIGH",
            pattern: /"alg"\s*:\s*"none"|eyJhbGc.*\.|"kid"\s*:\s*"\.\.\/|jwt-secret/i,
            summary: "JWT manipulation, none-algorithm, or path traversal in kid",
            confidence: "MEDIUM"
        },
        {
            category: "A04:2025-Insecure Design (GraphQL)",
            risk: "MEDIUM",
            pattern: /__schema|__type|graphql-playground|introspection/i,
            summary: "GraphQL introspection or schema probing",
            confidence: "MEDIUM"
        },

        /* ===================== MISCONFIG / INFO LEAK ===================== */


        {
            category: "A10:2025-Exception Leakage",
            risk: "MEDIUM",
            pattern: /StackTrace|NullPointerException|Fatal error|Traceback|ERR_HTTP_INVALID_CHAR|ERR_INVALID_URL|P2002|PrismaClientKnownRequestError/i,
            summary: "Application exception details or Prisma error leaked",
            confidence: "HIGH"
        },

        /* ===================== SUPPLY CHAIN ===================== */

        {
            category: "A03:2025-Software Supply Chain",
            risk: "HIGH",
            pattern: /Jenkins|CircleCI|Travis|GitHub Actions|\.github\/workflows|Dockerfile|docker-compose|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|\.npmrc|package\.json/i,
            summary: "CI/CD, dependency artifacts, or Node.js package targeting",
            confidence: "MEDIUM"
        }
    ];

    /* ===================== SCANNER ===================== */

    public static scan(rawLine: string): OWASPMatch[] {
        if (!rawLine) return [];

        // Fast Path: If the line doesn't contain any traditional exploit delivery characters, skip regex.
        // This avoids overhead for 90%+ of normal log lines (e.g. standard static assets or clean GETs).
        if (!/[{}$'"<>;|&`\(\)\[\]]/.test(rawLine)) {
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
                        immediate: rule.risk === "CRITICAL" || rule.risk === "HIGH",
                        confidence: rule.confidence,
                        cve: rule.cve
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
                        immediate: rule.risk === "CRITICAL" || rule.risk === "HIGH",
                        confidence: rule.confidence,
                        cve: rule.cve
                    });
                }
            }
            return matches;
        }
    }
}
