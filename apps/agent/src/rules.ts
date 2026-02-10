
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
            category: "A05:2025-Injection (SQLi)",
            risk: "HIGH",
            pattern: /union\s+all\s+select|insert\s+into|select\s+.*from|drop\s+table|update\s+.*set|' OR '1'='1|--|#|cast\(|md5\(|benchmark\(|char\(|concat\(|syscolumns|sysobjects/i,
            summary: "SQL Injection attempt detected in request parameters."
        },
        {
            category: "A05:2025-Injection (XSS)",
            risk: "HIGH",
            pattern: /<script|javascript:|onerror=|onload=|alert\(|confirm\(|prompt\(|document\.cookie|document\.location|window\.location|eval\(|atob\(|String\.fromCharCode/i,
            summary: "Cross-Site Scripting (XSS) payload detected."
        },
        {
            category: "A05:2025-Injection (Command)",
            risk: "HIGH",
            pattern: /;\s*(cat|ls|pwd|whoami|ifconfig|netstat|nmap|curl|wget|python|perl|bash|sh|nc|rm|mv|cp)\s|\|\|?\s*(cat|ls|pwd|whoami|ifconfig|netstat|nmap|curl|wget|python|perl|bash|sh|nc|rm|mv|cp)\s|`.*`|\$\(.*\)/i,
            summary: "Potential system command injection detected."
        },
        {
            category: "A01:2025-Broken Access Control (LFI/Traversal)",
            risk: "HIGH",
            pattern: /\.\.\/|\.\.\\|etc\/passwd|etc\/shadow|proc\/self|boot\.ini|win\.ini|Windows\\System32/i,
            summary: "Local File Inclusion or Path Traversal attempt."
        },
        {
            category: "A01:2025-Broken Access Control (Sensitive Files)",
            risk: "HIGH",
            pattern: /\.env|\.git|\.dockerconfigjson|\.ssh|config\.php|web\.config|\.htaccess|database\.yml|settings\.py|wp-config\.php/i,
            summary: "Attempt to access sensitive configuration or metadata files."
        },
        {
            category: "A01:2025-Broken Access Control (SSRF)",
            risk: "HIGH",
            pattern: /localhost|127\.0\.0\.1|169\.254\.169\.254|0\.0\.0\.0|\[::1\]|instance-data|metadata\.google/i,
            summary: "SSRF pattern detected targeting local or cloud metadata services."
        },
        {
            category: "A03:2025-Software Supply Chain Failures",
            risk: "HIGH",
            pattern: /jenkins|build\.xml|CircleCI|Traivs|package-lock\.json|yarn\.lock|composer\.lock|Dockerfile|docker-compose\.yml/i,
            summary: "Possible exposure or targeting of software supply chain artifacts."
        },
        {
            category: "A06:2025-Insecure Design (Information Disclosure)",
            risk: "MEDIUM",
            pattern: /phpinfo\(\)|server-status|server-info|\/admin\/|\/config\/|\/stats\//i,
            summary: "Attempt to access administrative or information disclosure endpoints."
        },
        {
            category: "A10:2025-Mishandling of Exceptional Conditions",
            risk: "MEDIUM",
            pattern: /Stacktrace|NullPointerException|Unhandled Exception|Internal Server Error|at\s+[\w\.]+\([\w\.]+\.java:\d+\)|Exception\s+in\s+thread/i,
            summary: "Leak of technical error details or mishandled exception detected."
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
                    immediate: rule.risk === "HIGH"
                };
            }
        }
        return null;
    }
}
