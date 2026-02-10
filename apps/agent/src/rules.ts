
export interface OWASPMatch {
    category: string;
    risk: "LOW" | "MEDIUM" | "HIGH";
    summary: string;
    action: string;
    immediate?: boolean;
}

export class OWASPScanner {
    private static rules = [
        {
            category: "A03:2021-Injection (SQLi)",
            risk: "HIGH",
            pattern: /union\s+select|insert\s+into|select\s+.*from|drop\s+table|update\s+.*set|' OR '1'='1|--|#|cast\(|md5\(|benchmark\(/i,
            summary: "SQL Injection attempt detected in request parameters."
        },
        {
            category: "A03:2021-Injection (XSS)",
            risk: "HIGH",
            pattern: /<script|javascript:|onerror=|onload=|alert\(|confirm\(|prompt\(|document\.cookie|document\.location|window\.location/i,
            summary: "Cross-Site Scripting (XSS) payload detected."
        },
        {
            category: "A03:2021-Injection (Command)",
            risk: "HIGH",
            pattern: /;\s*(cat|ls|pwd|whoami|ifconfig|netstat|nmap|curl|wget|python|perl|bash|sh|nc|rm|mv|cp)\s/i,
            summary: "Potential system command injection detected."
        },
        {
            category: "A01:2021-Broken Access Control (LFI/Traversal)",
            risk: "HIGH",
            pattern: /\.\.\/|\.\.\\|etc\/passwd|etc\/shadow|proc\/self|boot\.ini/i,
            summary: "Local File Inclusion or Path Traversal attempt."
        },
        {
            category: "A01:2021-Broken Access Control (Sensitive Files)",
            risk: "HIGH",
            pattern: /\.env|\.git|\.dockerconfigjson|\.ssh|config\.php|web\.config|\.htaccess/i,
            summary: "Attempt to access sensitive configuration or metadata files."
        },
        {
            category: "A10:2021-Server-Side Request Forgery (SSRF)",
            risk: "HIGH",
            pattern: /localhost|127\.0\.0\.1|169\.254\.169\.254|0\.0\.0\.0|\[::1\]/i,
            summary: "SSRF pattern detected targeting local or cloud metadata services."
        }
    ];

    public static scan(logLine: string): OWASPMatch | null {
        for (const rule of this.rules) {
            if (rule.pattern.test(logLine)) {
                return {
                    category: rule.category,
                    risk: rule.risk as any,
                    summary: rule.summary,
                    action: "Instant block recommended (Match: " + rule.category + ")",
                    immediate: rule.risk === "HIGH" // Auto-block HIGH risk OWASP matches
                };
            }
        }
        return null;
    }
}
