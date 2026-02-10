
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
            category: "A05:2025-Injection (RCE: React / Next.js)",
            risk: "CRITICAL",
            pattern: /__proto__|constructor\.prototype|__reactServerComponent__|getServerSideProps.*process\.env/i,
            summary: "Prototype pollution or React/Next.js server-side RCE vector",
            confidence: "MEDIUM"
        },

        /* ===================== INJECTION ===================== */

        {
            category: "A05:2025-Injection (SQLi)",
            risk: "HIGH",
            pattern: /union\s+all\s+select|select\s+.*from|sleep\(|benchmark\(|waitfor\s+delay|pg_sleep|load_file\(|into\s+outfile|' OR '1'='1|--|#|\/\*/i,
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
            pattern: /<script|javascript:|onerror=|onload=|alert\(|document\.cookie|data:text\/html|<svg|<iframe/i,
            summary: "Cross-site scripting payload detected",
            confidence: "HIGH"
        },
        {
            category: "A05:2025-Injection (OS Command)",
            risk: "HIGH",
            pattern: /(;|\|\||&&|`|\$\().*(sh|bash|curl|wget|nc|python|perl|php|rm|cat|ls|whoami)/i,
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
            pattern: /169\.254\.169\.254|metadata\.google\.internal|instance-data\.amazonaws\.com|localhost|127\.0\.0\.1|file:\/\//i,
            summary: "SSRF attempt targeting internal or cloud metadata services",
            confidence: "HIGH"
        },
        {
            category: "A01:2025-Broken Access Control (Path Traversal)",
            risk: "HIGH",
            pattern: /\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|\/proc\/self|win\.ini/i,
            summary: "Path traversal or local file inclusion attempt",
            confidence: "HIGH"
        },
        {
            category: "A01:2025-Broken Access Control (Sensitive Files)",
            risk: "HIGH",
            pattern: /\.env|\.git\/|id_rsa|\.dockerconfigjson|config\.ya?ml|secrets\.yml|\.kube\/config/i,
            summary: "Attempt to access secrets or configuration files",
            confidence: "HIGH"
        },

        /* ===================== DESERIALIZATION / XXE ===================== */

        {
            category: "A08:2025-Insecure Deserialization / XXE",
            risk: "HIGH",
            pattern: /<!DOCTYPE|<!ENTITY.*SYSTEM|ACED0005|rO0AB/i,
            summary: "Insecure deserialization or XXE payload detected",
            confidence: "HIGH"
        },

        /* ===================== AUTH / API ===================== */

        {
            category: "A07:2025-Authentication Failures (JWT)",
            risk: "HIGH",
            pattern: /"alg"\s*:\s*"none"|eyJhbGc.*\./i,
            summary: "JWT manipulation or none-algorithm attack",
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
            category: "A02:2025-Security Misconfiguration",
            risk: "MEDIUM",
            pattern: /phpinfo\(\)|server-status|actuator\/|swagger-ui|debug|trace\.axd|\.git\/HEAD/i,
            summary: "Debug endpoint or server information disclosure",
            confidence: "HIGH"
        },
        {
            category: "A10:2025-Exception Leakage",
            risk: "MEDIUM",
            pattern: /StackTrace|NullPointerException|Fatal error|Traceback \(most recent call last\)/i,
            summary: "Application exception details leaked",
            confidence: "HIGH"
        },

        /* ===================== SUPPLY CHAIN ===================== */

        {
            category: "A03:2025-Software Supply Chain",
            risk: "HIGH",
            pattern: /Jenkins|CircleCI|Travis|GitHub Actions|\.github\/workflows|Dockerfile|docker-compose|package-lock\.json|yarn\.lock/i,
            summary: "CI/CD or dependency artifact targeting",
            confidence: "MEDIUM"
        }
    ];

    /* ===================== SCANNER ===================== */

    public static scan(rawLine: string): OWASPMatch[] {
        if (!rawLine) return [];
        try {
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
            // If decode fails, fallback to raw line
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
