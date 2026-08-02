# =====================================================
# Builtin Pentest Intelligence
#
# Knowledge có sẵn khi Agent khởi tạo.
# Dùng làm nền cho reasoning/search của LLM.
# =====================================================
from .store import (
    IntelligenceStore,
    IntelligenceScenario,
    format_intelligence_context,
)
BUILTIN_SCENARIOS = [

    IntelligenceScenario(
        id="builtin-node-pm2-source-exposure",
        title="Node source exposure should check PM2 deployment files",
        category="recon-gap",

        triggers=[
            "node",
            "express",
            "server.js",
            "app.js",
            "index.js",
            "package.json",
            "pm2",
            "deployment",
            "nginx"
        ],

        technologies=[
            "Node.js",
            "Express",
            "PM2",
            "Nginx"
        ],

        lesson=(
            "When Node.js application source files or "
            "metadata are exposed, investigate deployment "
            "configuration files because they may reveal "
            "environment information, paths, services, "
            "or sensitive configuration."
        ),

        recommended_checks=[
            "ecosystem.config.js",
            "ecosystem.config.mjs",
            "pm2.json",
            "app.js",
            "index.js",
            "server.js",
            "server.js~",
            "package.json",
            "package-lock.json",
            "backup files",
            "archive files"
        ],

        avoid_missing=[
            "PM2 deployment configuration",
            "backup and archive variants",
            "environment secrets"
        ],

        source="builtin pentest knowledge",

        created_at="2026-01-01T00:00:00Z",

        confidence=0.95,

        scope="builtin"
    ),



    IntelligenceScenario(
        id="builtin-web-recon",
        title="Web reconnaissance should identify attack surface",

        category="recon",

        triggers=[
            "domain",
            "website",
            "web",
            "service",
            "port",
            "technology"
        ],

        technologies=[
            "Web"
        ],

        lesson=(
            "Before exploitation, perform reconnaissance "
            "to understand technologies, exposed services "
            "and possible attack surfaces."
        ),

        recommended_checks=[
            "nmap service detection",
            "technology fingerprinting",
            "directory enumeration",
            "subdomain discovery",
            "endpoint discovery"
        ],

        avoid_missing=[
            "hidden services",
            "backup files",
            "unmapped endpoints"
        ],

        source="builtin pentest knowledge",

        created_at="2026-01-01T00:00:00Z",

        confidence=0.95,

        scope="builtin"
    ),



    IntelligenceScenario(
        id="builtin-sqli-testing-pattern",

        title="SQL injection testing pattern",

        category="vulnerability",

        triggers=[
            "sql",
            "sqli",
            "parameter",
            "id",
            "login",
            "database"
        ],

        technologies=[
            "SQL",
            "Database",
            "Web"
        ],

        lesson=(
            "User-controlled parameters should be tested "
            "for SQL injection using manual validation "
            "and automated tools."
        ),

        recommended_checks=[
            "single quote testing",
            "boolean based SQL injection",
            "time based SQL injection",
            "union based SQL injection",
            "sqlmap verification"
        ],

        avoid_missing=[
            "blind SQL injection",
            "hidden parameters",
            "API endpoints"
        ],

        source="builtin pentest knowledge",

        created_at="2026-01-01T00:00:00Z",

        confidence=0.95,

        scope="builtin"
    ),



    IntelligenceScenario(
        id="builtin-xss-testing-pattern",

        title="Cross Site Scripting testing pattern",

        category="vulnerability",

        triggers=[
            "xss",
            "input",
            "html",
            "javascript",
            "search",
            "comment"
        ],

        technologies=[
            "Web"
        ],

        lesson=(
            "User input should be tested for reflected, "
            "stored and DOM-based XSS depending on "
            "execution context."
        ),

        recommended_checks=[
            "reflection testing",
            "HTML context analysis",
            "JavaScript context analysis",
            "DOM sink analysis"
        ],

        avoid_missing=[
            "stored XSS",
            "DOM XSS",
            "client side sinks"
        ],

        source="builtin pentest knowledge",

        created_at="2026-01-01T00:00:00Z",

        confidence=0.95,

        scope="builtin"
    ),



    IntelligenceScenario(
        id="builtin-auth-testing",

        title="Authentication and authorization testing",

        category="authentication",

        triggers=[
            "login",
            "session",
            "jwt",
            "cookie",
            "token",
            "authorization"
        ],

        technologies=[
            "Web",
            "API"
        ],

        lesson=(
            "Authentication mechanisms should be tested "
            "for weak tokens, session issues and broken "
            "access control."
        ),

        recommended_checks=[
            "JWT validation",
            "session management",
            "cookie security",
            "authorization testing",
            "privilege escalation"
        ],

        avoid_missing=[
            "broken access control",
            "session fixation",
            "token leakage"
        ],

        source="builtin pentest knowledge",

        created_at="2026-01-01T00:00:00Z",

        confidence=0.9,

        scope="builtin"
    )
]