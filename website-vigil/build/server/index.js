import { jsx, jsxs, Fragment } from "react/jsx-runtime";
import { PassThrough } from "node:stream";
import { createReadableStreamFromReadable } from "@react-router/node";
import { ServerRouter, UNSAFE_withComponentProps, Outlet, UNSAFE_withErrorBoundaryProps, isRouteErrorResponse, Meta, Links, ScrollRestoration, Scripts, useLocation, Link } from "react-router";
import { isbot } from "isbot";
import { renderToPipeableStream } from "react-dom/server";
const streamTimeout = 5e3;
function handleRequest(request, responseStatusCode, responseHeaders, routerContext, loadContext) {
  if (request.method.toUpperCase() === "HEAD") {
    return new Response(null, {
      status: responseStatusCode,
      headers: responseHeaders
    });
  }
  return new Promise((resolve, reject) => {
    let shellRendered = false;
    let userAgent = request.headers.get("user-agent");
    let readyOption = userAgent && isbot(userAgent) || routerContext.isSpaMode ? "onAllReady" : "onShellReady";
    let timeoutId = setTimeout(
      () => abort(),
      streamTimeout + 1e3
    );
    const { pipe, abort } = renderToPipeableStream(
      /* @__PURE__ */ jsx(ServerRouter, { context: routerContext, url: request.url }),
      {
        [readyOption]() {
          shellRendered = true;
          const body = new PassThrough({
            final(callback) {
              clearTimeout(timeoutId);
              timeoutId = void 0;
              callback();
            }
          });
          const stream = createReadableStreamFromReadable(body);
          responseHeaders.set("Content-Type", "text/html");
          pipe(body);
          resolve(
            new Response(stream, {
              headers: responseHeaders,
              status: responseStatusCode
            })
          );
        },
        onShellError(error) {
          reject(error);
        },
        onError(error) {
          responseStatusCode = 500;
          if (shellRendered) {
            console.error(error);
          }
        }
      }
    );
  });
}
const entryServer = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: handleRequest,
  streamTimeout
}, Symbol.toStringTag, { value: "Module" }));
const links = () => [{
  rel: "preconnect",
  href: "https://fonts.googleapis.com"
}, {
  rel: "preconnect",
  href: "https://fonts.gstatic.com",
  crossOrigin: "anonymous"
}, {
  rel: "stylesheet",
  href: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap"
}];
function Layout({
  children
}) {
  return /* @__PURE__ */ jsxs("html", {
    lang: "en",
    children: [/* @__PURE__ */ jsxs("head", {
      children: [/* @__PURE__ */ jsx("meta", {
        charSet: "utf-8"
      }), /* @__PURE__ */ jsx("meta", {
        name: "viewport",
        content: "width=device-width, initial-scale=1"
      }), /* @__PURE__ */ jsx(Meta, {}), /* @__PURE__ */ jsx(Links, {})]
    }), /* @__PURE__ */ jsxs("body", {
      children: [children, /* @__PURE__ */ jsx(ScrollRestoration, {}), /* @__PURE__ */ jsx(Scripts, {})]
    })]
  });
}
const root = UNSAFE_withComponentProps(function App() {
  return /* @__PURE__ */ jsx(Outlet, {});
});
const ErrorBoundary = UNSAFE_withErrorBoundaryProps(function ErrorBoundary2({
  error
}) {
  let message = "Oops!";
  let details = "An unexpected error occurred.";
  let stack;
  if (isRouteErrorResponse(error)) {
    message = error.status === 404 ? "404" : "Error";
    details = error.status === 404 ? "The requested page could not be found." : error.statusText || details;
  }
  return /* @__PURE__ */ jsxs("main", {
    style: {
      padding: "4rem 2rem",
      maxWidth: "800px",
      margin: "0 auto"
    },
    children: [/* @__PURE__ */ jsx("h1", {
      style: {
        fontSize: "3rem",
        fontWeight: 800,
        marginBottom: "1rem"
      },
      children: message
    }), /* @__PURE__ */ jsx("p", {
      style: {
        fontSize: "1.25rem",
        marginBottom: "2rem"
      },
      children: details
    }), stack]
  });
});
const route0 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  ErrorBoundary,
  Layout,
  default: root,
  links
}, Symbol.toStringTag, { value: "Module" }));
function Navbar() {
  const location = useLocation();
  const isActive = (path) => location.pathname === path;
  return /* @__PURE__ */ jsxs("nav", { className: "navbar", children: [
    /* @__PURE__ */ jsx(Link, { to: "/", className: "navbar-logo", children: "VIGIL" }),
    /* @__PURE__ */ jsxs("div", { className: "navbar-links", children: [
      /* @__PURE__ */ jsx(
        Link,
        {
          to: "/",
          className: `navbar-link ${isActive("/") ? "navbar-link-active" : ""}`,
          children: "Home"
        }
      ),
      /* @__PURE__ */ jsx(
        Link,
        {
          to: "/docs",
          className: `navbar-link ${isActive("/docs") ? "navbar-link-active" : ""}`,
          children: "Docs"
        }
      ),
      /* @__PURE__ */ jsx(
        Link,
        {
          to: "/about",
          className: `navbar-link ${isActive("/about") ? "navbar-link-active" : ""}`,
          children: "About"
        }
      ),
      /* @__PURE__ */ jsx(
        "a",
        {
          href: "https://github.com",
          target: "_blank",
          rel: "noopener noreferrer",
          className: "navbar-link",
          children: "GitHub"
        }
      )
    ] })
  ] });
}
function Hero() {
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-light-background)", paddingTop: "100px", paddingBottom: "100px" }, children: /* @__PURE__ */ jsx("div", { className: "container", children: /* @__PURE__ */ jsxs("div", { className: "two-column", children: [
    /* @__PURE__ */ jsxs("div", { children: [
      /* @__PURE__ */ jsx("div", { className: "badge mb-4", children: "Security Middleware" }),
      /* @__PURE__ */ jsx("h1", { className: "text-heading-xl", style: { marginBottom: "1.5rem", color: "var(--color-text)" }, children: "Security Middleware for Modern Web Applications" }),
      /* @__PURE__ */ jsx("p", { className: "text-body-lg", style: { marginBottom: "2rem", color: "#444", maxWidth: "540px" }, children: "VIGIL protects your Express.js applications automatically. Enterprise-grade security with zero configuration required. Block bots, prevent SQL injection, rate limit abuse, and verify emails — all in one package." }),
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", flexWrap: "wrap" }, children: [
        /* @__PURE__ */ jsx(Link, { to: "/docs", className: "btn-primary", children: "Get Started" }),
        /* @__PURE__ */ jsx(Link, { to: "/docs", className: "btn-secondary", children: "View Docs" })
      ] })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "brutalist-card", style: { backgroundColor: "white" }, children: [
      /* @__PURE__ */ jsx("h3", { style: { fontSize: "0.875rem", fontWeight: 700, marginBottom: "1rem", color: "#666", textTransform: "uppercase", letterSpacing: "0.1em" }, children: "Request Flow Through VIGIL Security Layer" }),
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", flexDirection: "column", gap: "0.75rem" }, children: [
        /* @__PURE__ */ jsx("div", { style: {
          padding: "1rem",
          border: "3px solid var(--color-border)",
          backgroundColor: "#f5f5f5",
          fontFamily: "var(--font-mono)",
          fontSize: "0.75rem"
        }, children: /* @__PURE__ */ jsx("span", { style: { color: "#666" }, children: "→ HTTP Request" }) }),
        /* @__PURE__ */ jsx("div", { style: { textAlign: "center", color: "var(--color-primary-blue)", fontWeight: 800 }, children: "↓" }),
        /* @__PURE__ */ jsxs("div", { style: {
          padding: "0.875rem",
          border: "3px solid var(--color-primary-blue)",
          backgroundColor: "var(--color-light-background)",
          boxShadow: "4px 4px 0px var(--color-primary-blue)",
          fontWeight: 600,
          fontSize: "0.875rem"
        }, children: [
          "🛡️ Rate Limiting",
          /* @__PURE__ */ jsx("span", { style: { display: "block", fontSize: "0.7rem", color: "#666", marginTop: "0.25rem" }, children: "Limits requests per IP" })
        ] }),
        /* @__PURE__ */ jsx("div", { style: { textAlign: "center", color: "var(--color-primary-blue)", fontWeight: 800 }, children: "↓" }),
        /* @__PURE__ */ jsxs("div", { style: {
          padding: "0.875rem",
          border: "3px solid var(--color-primary-blue)",
          backgroundColor: "var(--color-light-background)",
          boxShadow: "4px 4px 0px var(--color-primary-blue)",
          fontWeight: 600,
          fontSize: "0.875rem"
        }, children: [
          "🤖 Bot Detection",
          /* @__PURE__ */ jsx("span", { style: { display: "block", fontSize: "0.7rem", color: "#666", marginTop: "0.25rem" }, children: "Identifies malicious bots" })
        ] }),
        /* @__PURE__ */ jsx("div", { style: { textAlign: "center", color: "var(--color-primary-blue)", fontWeight: 800 }, children: "↓" }),
        /* @__PURE__ */ jsxs("div", { style: {
          padding: "0.875rem",
          border: "3px solid var(--color-primary-blue)",
          backgroundColor: "var(--color-light-background)",
          boxShadow: "4px 4px 0px var(--color-primary-blue)",
          fontWeight: 600,
          fontSize: "0.875rem"
        }, children: [
          "🔒 SQL Injection Guard",
          /* @__PURE__ */ jsx("span", { style: { display: "block", fontSize: "0.7rem", color: "#666", marginTop: "0.25rem" }, children: "Blocks SQL injection attacks" })
        ] }),
        /* @__PURE__ */ jsx("div", { style: { textAlign: "center", color: "var(--color-primary-blue)", fontWeight: 800 }, children: "↓" }),
        /* @__PURE__ */ jsxs("div", { style: {
          padding: "0.875rem",
          border: "3px solid var(--color-primary-blue)",
          backgroundColor: "var(--color-light-background)",
          boxShadow: "4px 4px 0px var(--color-primary-blue)",
          fontWeight: 600,
          fontSize: "0.875rem"
        }, children: [
          "✉️ Email Verification",
          /* @__PURE__ */ jsx("span", { style: { display: "block", fontSize: "0.7rem", color: "#666", marginTop: "0.25rem" }, children: "Verifies email addresses" })
        ] }),
        /* @__PURE__ */ jsx("div", { style: { textAlign: "center", color: "#22c55e", fontWeight: 800 }, children: "↓" }),
        /* @__PURE__ */ jsx("div", { style: {
          padding: "1rem",
          border: "3px solid #22c55e",
          backgroundColor: "#f0fdf4",
          boxShadow: "4px 4px 0px #22c55e",
          fontWeight: 600,
          fontSize: "0.875rem",
          textAlign: "center"
        }, children: "✓ Clean Request → Your App" })
      ] })
    ] })
  ] }) }) });
}
function ProblemSection() {
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-background)" }, children: /* @__PURE__ */ jsxs("div", { className: "container", children: [
    /* @__PURE__ */ jsxs("div", { style: { maxWidth: "800px", margin: "0 auto", textAlign: "center" }, children: [
      /* @__PURE__ */ jsx("h2", { className: "text-heading-lg", style: { marginBottom: "1rem" }, children: "The Security Gap in AI-Assisted Development" }),
      /* @__PURE__ */ jsx("p", { className: "text-body-lg", style: { color: "#666", marginBottom: "3rem" }, children: "AI coding assistants accelerate development but often skip critical security review. This creates a new class of vulnerabilities in production applications." })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "grid-3", children: [
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "48px",
          height: "48px",
          backgroundColor: "var(--color-primary-blue)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          border: "3px solid var(--color-border)",
          marginBottom: "1rem",
          fontSize: "1.5rem"
        }, children: "⚡" }),
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.75rem" }, children: "Rapid Prototyping" }),
        /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6 }, children: "AI tools generate code at lightning speed, but security considerations are often overlooked in the quest for faster iteration cycles." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "48px",
          height: "48px",
          backgroundColor: "#dc2626",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          border: "3px solid var(--color-border)",
          marginBottom: "1rem",
          fontSize: "1.5rem"
        }, children: "⚠️" }),
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.75rem" }, children: "Missing Security Reviews" }),
        /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6 }, children: "Traditional security workflows can't keep up with AI-accelerated development. Code reaches production without proper security auditing." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "48px",
          height: "48px",
          backgroundColor: "#ea580c",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          border: "3px solid var(--color-border)",
          marginBottom: "1rem",
          fontSize: "1.5rem"
        }, children: "🔓" }),
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.75rem" }, children: "Common Vulnerabilities" }),
        /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6 }, children: "SQL injection, XSS, CSRF, and rate limiting vulnerabilities become commonplace when security is treated as an afterthought." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "48px",
          height: "48px",
          backgroundColor: "#7c3aed",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          border: "3px solid var(--color-border)",
          marginBottom: "1rem",
          fontSize: "1.5rem"
        }, children: "🔧" }),
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.75rem" }, children: "Complex Security Tooling" }),
        /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6 }, children: "Existing security solutions require steep learning curves, multiple integrations, and significant configuration overhead." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "48px",
          height: "48px",
          backgroundColor: "#0891b2",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          border: "3px solid var(--color-border)",
          marginBottom: "1rem",
          fontSize: "1.5rem"
        }, children: "🏗️" }),
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.75rem" }, children: "Infrastructure vs Application" }),
        /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6 }, children: "WAFs and network firewalls operate at the infrastructure layer, lacking context about application-specific threats." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "48px",
          height: "48px",
          backgroundColor: "#be185d",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          border: "3px solid var(--color-border)",
          marginBottom: "1rem",
          fontSize: "1.5rem"
        }, children: "💸" }),
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.75rem" }, children: "Resource Drain" }),
        /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6 }, children: "Building custom security solutions drains development resources and distracts from core product development." })
      ] })
    ] })
  ] }) });
}
function HowVigilWorks() {
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-light-background)" }, children: /* @__PURE__ */ jsxs("div", { className: "container", children: [
    /* @__PURE__ */ jsxs("div", { style: { textAlign: "center", marginBottom: "4rem" }, children: [
      /* @__PURE__ */ jsx("h2", { className: "text-heading-lg", style: { marginBottom: "1rem" }, children: "How VIGIL Works" }),
      /* @__PURE__ */ jsx("p", { className: "text-body-lg", style: { color: "#666", maxWidth: "600px", margin: "0 auto" }, children: "VIGIL sits between the HTTP request and your application logic, providing comprehensive threat detection and policy enforcement." })
    ] }),
    /* @__PURE__ */ jsxs("div", { className: "brutalist-card", style: { maxWidth: "900px", margin: "0 auto", padding: "2rem" }, children: [
      /* @__PURE__ */ jsx("h3", { style: { fontSize: "1rem", fontWeight: 700, marginBottom: "2rem", color: "#666", textTransform: "uppercase", letterSpacing: "0.1em", textAlign: "center" }, children: "Middleware Architecture" }),
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", flexDirection: "column", gap: "1rem" }, children: [
        /* @__PURE__ */ jsxs("div", { style: { display: "flex", alignItems: "center", gap: "1rem" }, children: [
          /* @__PURE__ */ jsx("div", { style: {
            flex: 1,
            padding: "1.5rem",
            backgroundColor: "#f5f5f5",
            border: "3px solid var(--color-border)",
            textAlign: "center",
            fontWeight: 600
          }, children: "🌐 HTTP Request" }),
          /* @__PURE__ */ jsx("div", { style: { color: "var(--color-primary-blue)", fontSize: "1.5rem", fontWeight: 800 }, children: "→" }),
          /* @__PURE__ */ jsx("div", { style: {
            flex: 1,
            padding: "1.5rem",
            backgroundColor: "var(--color-primary-blue)",
            border: "3px solid var(--color-border)",
            color: "white",
            textAlign: "center",
            fontWeight: 700,
            boxShadow: "4px 4px 0px black"
          }, children: "VIGIL Security Layer" })
        ] }),
        /* @__PURE__ */ jsx("div", { style: { textAlign: "center", fontSize: "1.5rem", color: "var(--color-primary-blue)", fontWeight: 800 }, children: "↓" }),
        /* @__PURE__ */ jsxs("div", { style: { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1rem" }, children: [
          /* @__PURE__ */ jsxs("div", { style: {
            padding: "1.25rem",
            backgroundColor: "white",
            border: "3px solid var(--color-border)",
            textAlign: "center",
            boxShadow: "4px 4px 0px black"
          }, children: [
            /* @__PURE__ */ jsx("div", { style: { fontSize: "1.5rem", marginBottom: "0.5rem" }, children: "🔍" }),
            /* @__PURE__ */ jsx("div", { style: { fontWeight: 700, fontSize: "0.875rem" }, children: "1. Request Inspection" }),
            /* @__PURE__ */ jsx("div", { style: { fontSize: "0.75rem", color: "#666", marginTop: "0.5rem" }, children: "Analyze headers, body, and parameters" })
          ] }),
          /* @__PURE__ */ jsxs("div", { style: {
            padding: "1.25rem",
            backgroundColor: "white",
            border: "3px solid var(--color-border)",
            textAlign: "center",
            boxShadow: "4px 4px 0px black"
          }, children: [
            /* @__PURE__ */ jsx("div", { style: { fontSize: "1.5rem", marginBottom: "0.5rem" }, children: "🛡️" }),
            /* @__PURE__ */ jsx("div", { style: { fontWeight: 700, fontSize: "0.875rem" }, children: "2. Threat Detection" }),
            /* @__PURE__ */ jsx("div", { style: { fontSize: "0.75rem", color: "#666", marginTop: "0.5rem" }, children: "Run security checks against rules" })
          ] }),
          /* @__PURE__ */ jsxs("div", { style: {
            padding: "1.25rem",
            backgroundColor: "white",
            border: "3px solid var(--color-border)",
            textAlign: "center",
            boxShadow: "4px 4px 0px black"
          }, children: [
            /* @__PURE__ */ jsx("div", { style: { fontSize: "1.5rem", marginBottom: "0.5rem" }, children: "⚖️" }),
            /* @__PURE__ */ jsx("div", { style: { fontWeight: 700, fontSize: "0.875rem" }, children: "3. Policy Enforcement" }),
            /* @__PURE__ */ jsx("div", { style: { fontSize: "0.75rem", color: "#666", marginTop: "0.5rem" }, children: "Allow, block, or challenge request" })
          ] })
        ] }),
        /* @__PURE__ */ jsx("div", { style: { textAlign: "center", fontSize: "1.5rem", color: "#22c55e", fontWeight: 800 }, children: "↓" }),
        /* @__PURE__ */ jsxs("div", { style: { display: "flex", alignItems: "center", gap: "1rem" }, children: [
          /* @__PURE__ */ jsx("div", { style: {
            flex: 1,
            padding: "1rem",
            backgroundColor: "#f0fdf4",
            border: "3px solid #22c55e",
            textAlign: "center",
            fontWeight: 600,
            fontSize: "0.875rem"
          }, children: "✓ Pass → Your Express App" }),
          /* @__PURE__ */ jsx("div", { style: { color: "#dc2626", fontSize: "1.5rem", fontWeight: 800 }, children: "|" }),
          /* @__PURE__ */ jsx("div", { style: {
            flex: 1,
            padding: "1rem",
            backgroundColor: "#fef2f2",
            border: "3px solid #dc2626",
            textAlign: "center",
            fontWeight: 600,
            fontSize: "0.875rem"
          }, children: "✕ Block → 403 Forbidden" }),
          /* @__PURE__ */ jsx("div", { style: { color: "#f59e0b", fontSize: "1.5rem", fontWeight: 800 }, children: "|" }),
          /* @__PURE__ */ jsx("div", { style: {
            flex: 1,
            padding: "1rem",
            backgroundColor: "#fffbeb",
            border: "3px solid #f59e0b",
            textAlign: "center",
            fontWeight: 600,
            fontSize: "0.875rem"
          }, children: "⚠ Challenge → CAPTCHA" })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxs("div", { style: { display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "2rem", marginTop: "3rem", maxWidth: "900px", margin: "3rem auto 0" }, children: [
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", alignItems: "flex-start" }, children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "32px",
          height: "32px",
          backgroundColor: "var(--color-primary-blue)",
          color: "white",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 800,
          flexShrink: 0
        }, children: "1" }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("h4", { style: { fontWeight: 700, marginBottom: "0.5rem" }, children: "Zero Configuration" }),
          /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: "VIGIL works out of the box with sensible defaults. Add the middleware and you're protected immediately." })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", alignItems: "flex-start" }, children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "32px",
          height: "32px",
          backgroundColor: "var(--color-primary-blue)",
          color: "white",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 800,
          flexShrink: 0
        }, children: "2" }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("h4", { style: { fontWeight: 700, marginBottom: "0.5rem" }, children: "Modular Architecture" }),
          /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: "Enable or disable specific security modules based on your application's needs." })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", alignItems: "flex-start" }, children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "32px",
          height: "32px",
          backgroundColor: "var(--color-primary-blue)",
          color: "white",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 800,
          flexShrink: 0
        }, children: "3" }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("h4", { style: { fontWeight: 700, marginBottom: "0.5rem" }, children: "Request Context" }),
          /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: "Unlike WAFs, VIGIL understands your application's specific context and can make smarter decisions." })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", alignItems: "flex-start" }, children: [
        /* @__PURE__ */ jsx("div", { style: {
          width: "32px",
          height: "32px",
          backgroundColor: "var(--color-primary-blue)",
          color: "white",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 800,
          flexShrink: 0
        }, children: "4" }),
        /* @__PURE__ */ jsxs("div", { children: [
          /* @__PURE__ */ jsx("h4", { style: { fontWeight: 700, marginBottom: "0.5rem" }, children: "Developer Friendly" }),
          /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: "Clear error messages, detailed logs, and intuitive APIs make debugging straightforward." })
        ] })
      ] })
    ] })
  ] }) });
}
const securityModules = [
  {
    icon: "⚡",
    title: "Rate Limiting",
    description: "Protect your API from abuse and DDoS attacks with intelligent rate limiting.",
    features: [
      "Configurable request limits",
      "IP-based and user-based throttling",
      "Sliding window algorithm",
      "Custom response headers"
    ]
  },
  {
    icon: "🤖",
    title: "Bot Detection",
    description: "Identify and block malicious bots while allowing legitimate traffic.",
    features: [
      "Behavioral analysis",
      "Headless browser detection",
      "Signature-based blocking",
      "CAPTCHA integration"
    ]
  },
  {
    icon: "🔒",
    title: "SQL Injection Guard",
    description: "Prevent SQL injection attacks with real-time query analysis.",
    features: [
      "Query parameter scanning",
      "Pattern-based detection",
      "Whitelist/blacklist support",
      "Detailed attack logging"
    ]
  },
  {
    icon: "✉️",
    title: "Email Verification",
    description: "Verify email addresses to reduce spam and fake accounts.",
    features: [
      "MX record validation",
      "Disposable email detection",
      "SMTP verification",
      "Rate limiting per email"
    ]
  },
  {
    icon: "📊",
    title: "Request Monitoring",
    description: "Comprehensive logging and analytics for security insights.",
    features: [
      "Real-time request logs",
      "Attack pattern detection",
      "Dashboard integration",
      "Alert system"
    ]
  },
  {
    icon: "⚙️",
    title: "Policy Enforcement",
    description: "Define and enforce security policies across your application.",
    features: [
      "Custom security rules",
      "IP allowlist/blocklist",
      "Geographic restrictions",
      "Time-based access control"
    ]
  }
];
function FeatureGrid() {
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-background)" }, children: /* @__PURE__ */ jsxs("div", { className: "container", children: [
    /* @__PURE__ */ jsxs("div", { style: { textAlign: "center", marginBottom: "4rem" }, children: [
      /* @__PURE__ */ jsx("h2", { className: "text-heading-lg", style: { marginBottom: "1rem" }, children: "Security Modules" }),
      /* @__PURE__ */ jsx("p", { className: "text-body-lg", style: { color: "#666", maxWidth: "600px", margin: "0 auto" }, children: "Six powerful security modules working together to protect your application from modern threats." })
    ] }),
    /* @__PURE__ */ jsx("div", { className: "grid-3", children: securityModules.map((module, index) => /* @__PURE__ */ jsxs("div", { className: "brutalist-card-blue", style: { height: "100%" }, children: [
      /* @__PURE__ */ jsx("div", { style: {
        width: "56px",
        height: "56px",
        backgroundColor: "var(--color-primary-blue)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        border: "3px solid var(--color-border)",
        marginBottom: "1.25rem",
        fontSize: "1.75rem"
      }, children: module.icon }),
      /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.75rem" }, children: module.title }),
      /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, marginBottom: "1rem", fontSize: "0.875rem" }, children: module.description }),
      /* @__PURE__ */ jsx("ul", { style: { listStyle: "none", padding: 0, margin: 0 }, children: module.features.map((feature, idx) => /* @__PURE__ */ jsxs("li", { style: {
        display: "flex",
        alignItems: "center",
        gap: "0.5rem",
        padding: "0.375rem 0",
        fontSize: "0.8rem",
        color: "#444"
      }, children: [
        /* @__PURE__ */ jsx("span", { style: { color: "var(--color-primary-blue)", fontWeight: 800 }, children: "✓" }),
        feature
      ] }, idx)) })
    ] }, index)) })
  ] }) });
}
function ArchitectureDiagram() {
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-light-background)" }, children: /* @__PURE__ */ jsxs("div", { className: "container", children: [
    /* @__PURE__ */ jsxs("div", { style: { textAlign: "center", marginBottom: "4rem" }, children: [
      /* @__PURE__ */ jsx("h2", { className: "text-heading-lg", style: { marginBottom: "1rem" }, children: "Architecture Comparison" }),
      /* @__PURE__ */ jsx("p", { className: "text-body-lg", style: { color: "#666", maxWidth: "700px", margin: "0 auto" }, children: "See how VIGIL's application-layer security compares to traditional infrastructure solutions." })
    ] }),
    /* @__PURE__ */ jsx("div", { style: { overflowX: "auto", marginBottom: "3rem" }, children: /* @__PURE__ */ jsxs("table", { className: "brutalist-table", style: { minWidth: "800px" }, children: [
      /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
        /* @__PURE__ */ jsx("th", { style: { width: "30%" }, children: "Feature" }),
        /* @__PURE__ */ jsx("th", { style: { width: "23%", backgroundColor: "#666" }, children: "WAF" }),
        /* @__PURE__ */ jsx("th", { style: { width: "23%", backgroundColor: "#666" }, children: "Network Firewall" }),
        /* @__PURE__ */ jsx("th", { style: { width: "23%", backgroundColor: "var(--color-primary-blue)" }, children: "VIGIL" })
      ] }) }),
      /* @__PURE__ */ jsxs("tbody", { children: [
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "Layer" }),
          /* @__PURE__ */ jsx("td", { children: "Network/Transport" }),
          /* @__PURE__ */ jsx("td", { children: "Network" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600 }, children: "Application" })
        ] }),
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "Request Context" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "Limited" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "None" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600 }, children: "Full Access" })
        ] }),
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "SQL Injection Protection" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "Basic patterns" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "✕" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600 }, children: "✓ Advanced" })
        ] }),
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "Bot Detection" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "Limited" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "✕" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600 }, children: "✓ Behavioral" })
        ] }),
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "Rate Limiting" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "✓" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "✓" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600 }, children: "✓ Granular" })
        ] }),
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "Email Verification" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "✕" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "✕" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600 }, children: "✓ Built-in" })
        ] }),
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "Integration Effort" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#f59e0b" }, children: "High" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#f59e0b" }, children: "High" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600, color: "#22c55e" }, children: "Low (2 lines)" })
        ] }),
        /* @__PURE__ */ jsxs("tr", { children: [
          /* @__PURE__ */ jsx("td", { style: { fontWeight: 600 }, children: "Developer Control" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "Limited" }),
          /* @__PURE__ */ jsx("td", { style: { color: "#666" }, children: "None" }),
          /* @__PURE__ */ jsx("td", { style: { backgroundColor: "#dbeafe", fontWeight: 600 }, children: "Full" })
        ] })
      ] })
    ] }) }),
    /* @__PURE__ */ jsxs("div", { style: { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "2rem", marginTop: "3rem" }, children: [
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", style: { textAlign: "center" }, children: [
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1rem", fontWeight: 700, marginBottom: "1rem", color: "#666" }, children: "Traditional Tools" }),
        /* @__PURE__ */ jsxs("div", { style: {
          border: "3px dashed #999",
          padding: "1.5rem",
          marginBottom: "1rem",
          backgroundColor: "#f9f9f9"
        }, children: [
          /* @__PURE__ */ jsx("div", { style: { fontSize: "0.75rem", color: "#666", marginBottom: "0.5rem" }, children: "INFRASTRUCTURE LAYER" }),
          /* @__PURE__ */ jsx("div", { style: { fontWeight: 700, fontSize: "0.875rem" }, children: "WAF / Firewall" })
        ] }),
        /* @__PURE__ */ jsxs("div", { style: {
          border: "3px dashed #999",
          padding: "1.5rem",
          backgroundColor: "#f9f9f9",
          opacity: 0.5
        }, children: [
          /* @__PURE__ */ jsx("div", { style: { fontSize: "0.75rem", color: "#666", marginBottom: "0.5rem" }, children: "APPLICATION LAYER" }),
          /* @__PURE__ */ jsx("div", { style: { fontWeight: 700, fontSize: "0.875rem", color: "#999" }, children: "Your App" })
        ] }),
        /* @__PURE__ */ jsx("p", { style: { fontSize: "0.8rem", color: "#666", marginTop: "1rem" }, children: "Operate at infrastructure layer with limited visibility into application context" })
      ] }),
      /* @__PURE__ */ jsx("div", { style: { display: "flex", alignItems: "center", justifyContent: "center", fontSize: "2rem", color: "var(--color-primary-blue)" }, children: "→" }),
      /* @__PURE__ */ jsxs("div", { className: "brutalist-card", style: { textAlign: "center", borderColor: "var(--color-primary-blue)" }, children: [
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1rem", fontWeight: 700, marginBottom: "1rem", color: "var(--color-primary-blue)" }, children: "VIGIL" }),
        /* @__PURE__ */ jsxs("div", { style: {
          border: "3px solid var(--color-primary-blue)",
          padding: "1.5rem",
          marginBottom: "1rem",
          backgroundColor: "var(--color-light-background)",
          boxShadow: "4px 4px 0px var(--color-primary-blue)"
        }, children: [
          /* @__PURE__ */ jsx("div", { style: { fontSize: "0.75rem", color: "var(--color-primary-blue)", marginBottom: "0.5rem" }, children: "APPLICATION LAYER" }),
          /* @__PURE__ */ jsx("div", { style: { fontWeight: 700, fontSize: "0.875rem" }, children: "VIGIL Security" })
        ] }),
        /* @__PURE__ */ jsxs("div", { style: {
          border: "3px solid #22c55e",
          padding: "1.5rem",
          backgroundColor: "#f0fdf4"
        }, children: [
          /* @__PURE__ */ jsx("div", { style: { fontSize: "0.75rem", color: "#22c55e", marginBottom: "0.5rem" }, children: "APPLICATION LAYER" }),
          /* @__PURE__ */ jsx("div", { style: { fontWeight: 700, fontSize: "0.875rem", color: "#22c55e" }, children: "Your App" })
        ] }),
        /* @__PURE__ */ jsx("p", { style: { fontSize: "0.8rem", color: "#666", marginTop: "1rem" }, children: "Sits within your app with full context awareness and simple integration" })
      ] })
    ] })
  ] }) });
}
function IntegrationSection() {
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-background)" }, children: /* @__PURE__ */ jsxs("div", { className: "container", children: [
    /* @__PURE__ */ jsxs("div", { style: { textAlign: "center", marginBottom: "4rem" }, children: [
      /* @__PURE__ */ jsx("h2", { className: "text-heading-lg", style: { marginBottom: "1rem" }, children: "Simple Integration" }),
      /* @__PURE__ */ jsx("p", { className: "text-body-lg", style: { color: "#666", maxWidth: "600px", margin: "0 auto" }, children: "Add enterprise-grade security to your Express.js app in under 2 minutes." })
    ] }),
    /* @__PURE__ */ jsxs("div", { style: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: "3rem", alignItems: "start" }, children: [
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsxs("div", { className: "brutalist-card", children: [
          /* @__PURE__ */ jsx("h3", { style: { fontSize: "1rem", fontWeight: 700, marginBottom: "1rem", color: "#666", textTransform: "uppercase", letterSpacing: "0.1em" }, children: "Step 1: Install" }),
          /* @__PURE__ */ jsxs("div", { className: "code-block", style: { padding: "1rem" }, children: [
            /* @__PURE__ */ jsx("span", { style: { color: "#6272a4" }, children: "$" }),
            " npm install vigil-security"
          ] })
        ] }),
        /* @__PURE__ */ jsxs("div", { className: "brutalist-card", style: { marginTop: "1.5rem" }, children: [
          /* @__PURE__ */ jsx("h3", { style: { fontSize: "1rem", fontWeight: 700, marginBottom: "1rem", color: "#666", textTransform: "uppercase", letterSpacing: "0.1em" }, children: "Step 2: Configure" }),
          /* @__PURE__ */ jsx("div", { className: "code-block", children: `import express from 'express';
import { vigil } from 'vigil-security';

const app = express();

// Add VIGIL middleware
app.use(vigil());

// Your routes
app.get('/', (req, res) => {
  res.json({ message: 'Secure!' });
});

app.listen(3000);` })
        ] })
      ] }),
      /* @__PURE__ */ jsxs("div", { children: [
        /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.5rem", fontWeight: 700, marginBottom: "1.5rem" }, children: "That's It! ✓" }),
        /* @__PURE__ */ jsxs("div", { style: { display: "flex", flexDirection: "column", gap: "1.5rem" }, children: [
          /* @__PURE__ */ jsx("div", { className: "brutalist-card-blue", style: { padding: "1.25rem" }, children: /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", alignItems: "flex-start" }, children: [
            /* @__PURE__ */ jsx("div", { style: {
              width: "32px",
              height: "32px",
              backgroundColor: "var(--color-primary-blue)",
              color: "white",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              flexShrink: 0
            }, children: "1" }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("h4", { style: { fontWeight: 700, marginBottom: "0.5rem" }, children: "Zero Configuration" }),
              /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: "The above code enables all security modules with sensible defaults. Your app is protected immediately." })
            ] })
          ] }) }),
          /* @__PURE__ */ jsx("div", { className: "brutalist-card-blue", style: { padding: "1.25rem" }, children: /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", alignItems: "flex-start" }, children: [
            /* @__PURE__ */ jsx("div", { style: {
              width: "32px",
              height: "32px",
              backgroundColor: "var(--color-primary-blue)",
              color: "white",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              flexShrink: 0
            }, children: "2" }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("h4", { style: { fontWeight: 700, marginBottom: "0.5rem" }, children: "Customize as Needed" }),
              /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: "Pass options to enable specific modules or override defaults:" }),
              /* @__PURE__ */ jsx("div", { className: "code-block", style: { marginTop: "0.75rem", padding: "0.75rem", fontSize: "0.75rem" }, children: `vigil({
  rateLimit: { windowMs: 60000, max: 100 },
  botDetection: { enabled: true },
  sqlGuard: { enabled: true },
  emailVerification: { enabled: false }
})` })
            ] })
          ] }) }),
          /* @__PURE__ */ jsx("div", { className: "brutalist-card-blue", style: { padding: "1.25rem" }, children: /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", alignItems: "flex-start" }, children: [
            /* @__PURE__ */ jsx("div", { style: {
              width: "32px",
              height: "32px",
              backgroundColor: "var(--color-primary-blue)",
              color: "white",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: 800,
              flexShrink: 0
            }, children: "3" }),
            /* @__PURE__ */ jsxs("div", { children: [
              /* @__PURE__ */ jsx("h4", { style: { fontWeight: 700, marginBottom: "0.5rem" }, children: "TypeScript Support" }),
              /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: "Full TypeScript support with automatic type inference. IntelliSense for all configuration options." })
            ] })
          ] }) })
        ] })
      ] })
    ] })
  ] }) });
}
function DeveloperExperience() {
  const features = [
    {
      icon: "🚀",
      title: "Zero Configuration",
      description: "Get started in seconds. VIGIL works out of the box with sensible defaults for all security modules."
    },
    {
      icon: "🧩",
      title: "Modular Architecture",
      description: "Enable or disable specific modules. Import only what you need. Full control over your security stack."
    },
    {
      icon: "⚡",
      title: "Fast Integration",
      description: "Two lines of code to protect your entire application. No complex setup or external services required."
    },
    {
      icon: "💨",
      title: "Lightweight Runtime",
      description: "Minimal performance overhead. Sub-millisecond latency for most security checks."
    },
    {
      icon: "📦",
      title: "Express.js Compatible",
      description: "Built specifically for Express.js. Works seamlessly with your existing middleware and routes."
    },
    {
      icon: "🔧",
      title: "Developer Friendly",
      description: "Clear error messages, comprehensive logging, and intuitive APIs make debugging easy."
    }
  ];
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-light-background)" }, children: /* @__PURE__ */ jsxs("div", { className: "container", children: [
    /* @__PURE__ */ jsxs("div", { style: { textAlign: "center", marginBottom: "4rem" }, children: [
      /* @__PURE__ */ jsx("h2", { className: "text-heading-lg", style: { marginBottom: "1rem" }, children: "Developer Experience" }),
      /* @__PURE__ */ jsx("p", { className: "text-body-lg", style: { color: "#666", maxWidth: "600px", margin: "0 auto" }, children: "Built by developers, for developers. Security that doesn't get in your way." })
    ] }),
    /* @__PURE__ */ jsx("div", { className: "grid-3", children: features.map((feature, index) => /* @__PURE__ */ jsxs("div", { className: "brutalist-card", style: { height: "100%" }, children: [
      /* @__PURE__ */ jsx("div", { style: {
        fontSize: "2rem",
        marginBottom: "1rem"
      }, children: feature.icon }),
      /* @__PURE__ */ jsx("h3", { style: { fontSize: "1.125rem", fontWeight: 700, marginBottom: "0.75rem" }, children: feature.title }),
      /* @__PURE__ */ jsx("p", { style: { color: "#666", lineHeight: 1.6, fontSize: "0.875rem" }, children: feature.description })
    ] }, index)) }),
    /* @__PURE__ */ jsxs("div", { style: {
      display: "grid",
      gridTemplateColumns: "repeat(4, 1fr)",
      gap: "2rem",
      marginTop: "4rem",
      padding: "2rem",
      backgroundColor: "var(--color-primary-blue)",
      border: "3px solid var(--color-border)",
      boxShadow: "var(--brutalist-shadow)"
    }, children: [
      /* @__PURE__ */ jsxs("div", { style: { textAlign: "center" }, children: [
        /* @__PURE__ */ jsx("div", { style: { fontSize: "2.5rem", fontWeight: 800, color: "white" }, children: "2" }),
        /* @__PURE__ */ jsx("div", { style: { fontSize: "0.875rem", color: "rgba(255,255,255,0.8)" }, children: "Lines of Code" })
      ] }),
      /* @__PURE__ */ jsxs("div", { style: { textAlign: "center" }, children: [
        /* @__PURE__ */ jsx("div", { style: { fontSize: "2.5rem", fontWeight: 800, color: "white" }, children: "6" }),
        /* @__PURE__ */ jsx("div", { style: { fontSize: "0.875rem", color: "rgba(255,255,255,0.8)" }, children: "Security Modules" })
      ] }),
      /* @__PURE__ */ jsxs("div", { style: { textAlign: "center" }, children: [
        /* @__PURE__ */ jsxs("div", { style: { fontSize: "2.5rem", fontWeight: 800, color: "white" }, children: [
          "<",
          "1ms"
        ] }),
        /* @__PURE__ */ jsx("div", { style: { fontSize: "0.875rem", color: "rgba(255,255,255,0.8)" }, children: "Latency" })
      ] }),
      /* @__PURE__ */ jsxs("div", { style: { textAlign: "center" }, children: [
        /* @__PURE__ */ jsx("div", { style: { fontSize: "2.5rem", fontWeight: 800, color: "white" }, children: "100%" }),
        /* @__PURE__ */ jsx("div", { style: { fontSize: "0.875rem", color: "rgba(255,255,255,0.8)" }, children: "TypeScript" })
      ] })
    ] })
  ] }) });
}
function CTASection() {
  return /* @__PURE__ */ jsx("section", { className: "section", style: { backgroundColor: "var(--color-primary-blue)", paddingBottom: "100px" }, children: /* @__PURE__ */ jsxs("div", { className: "container", style: { textAlign: "center" }, children: [
    /* @__PURE__ */ jsx("h2", { className: "text-heading-lg", style: { marginBottom: "1rem", color: "white" }, children: "Ready to Secure Your Application?" }),
    /* @__PURE__ */ jsx("p", { style: { color: "rgba(255,255,255,0.9)", fontSize: "1.125rem", marginBottom: "2rem", maxWidth: "500px", margin: "0 auto 2rem" }, children: "Add VIGIL to your Express.js app in under 2 minutes. Start with zero configuration." }),
    /* @__PURE__ */ jsxs("div", { style: { display: "flex", gap: "1rem", justifyContent: "center", flexWrap: "wrap" }, children: [
      /* @__PURE__ */ jsx(
        Link,
        {
          to: "/docs",
          className: "btn-secondary",
          style: { backgroundColor: "white", borderColor: "white" },
          children: "Read Documentation"
        }
      ),
      /* @__PURE__ */ jsx(
        "a",
        {
          href: "https://github.com",
          target: "_blank",
          rel: "noopener noreferrer",
          className: "btn-secondary",
          style: { backgroundColor: "var(--color-primary-blue)", color: "white", borderColor: "white" },
          children: "View on GitHub"
        }
      )
    ] })
  ] }) });
}
function Footer() {
  const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
  return /* @__PURE__ */ jsx("footer", { className: "footer", children: /* @__PURE__ */ jsxs("div", { className: "container", children: [
    /* @__PURE__ */ jsxs("div", { className: "footer-content", children: [
      /* @__PURE__ */ jsxs("div", { className: "footer-section", style: { maxWidth: "300px" }, children: [
        /* @__PURE__ */ jsx("h4", { style: { color: "white", fontWeight: 800, fontSize: "1.5rem" }, children: "VIGIL" }),
        /* @__PURE__ */ jsx("p", { style: { color: "#a0a0a0", lineHeight: 1.6 }, children: "Security middleware for modern web applications. Protect your Express.js apps with enterprise-grade security." })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "footer-section", children: [
        /* @__PURE__ */ jsx("h4", { children: "Product" }),
        /* @__PURE__ */ jsx(Link, { to: "/docs", children: "Documentation" }),
        /* @__PURE__ */ jsx(Link, { to: "/about", children: "About" }),
        /* @__PURE__ */ jsx("a", { href: "https://github.com", target: "_blank", rel: "noopener noreferrer", children: "GitHub" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "Changelog" })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "footer-section", children: [
        /* @__PURE__ */ jsx("h4", { children: "Resources" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "API Reference" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "Examples" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "Blog" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "Community" })
      ] }),
      /* @__PURE__ */ jsxs("div", { className: "footer-section", children: [
        /* @__PURE__ */ jsx("h4", { children: "Legal" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "Privacy Policy" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "Terms of Service" }),
        /* @__PURE__ */ jsx("a", { href: "#", children: "License" })
      ] })
    ] }),
    /* @__PURE__ */ jsx("div", { className: "footer-bottom", children: /* @__PURE__ */ jsxs("p", { children: [
      "© ",
      currentYear,
      " VIGIL Security. All rights reserved."
    ] }) })
  ] }) });
}
function meta$2({}) {
  return [{
    title: "VIGIL - Security Middleware for Modern Web Applications"
  }, {
    name: "description",
    content: "Enterprise-grade security middleware for Express.js. Protect your applications with rate limiting, bot detection, SQL injection guard, and email verification."
  }];
}
const home = UNSAFE_withComponentProps(function Home() {
  return /* @__PURE__ */ jsxs(Fragment, {
    children: [/* @__PURE__ */ jsx(Navbar, {}), /* @__PURE__ */ jsxs("main", {
      children: [/* @__PURE__ */ jsx(Hero, {}), /* @__PURE__ */ jsx(ProblemSection, {}), /* @__PURE__ */ jsx(HowVigilWorks, {}), /* @__PURE__ */ jsx(FeatureGrid, {}), /* @__PURE__ */ jsx(ArchitectureDiagram, {}), /* @__PURE__ */ jsx(IntegrationSection, {}), /* @__PURE__ */ jsx(DeveloperExperience, {}), /* @__PURE__ */ jsx(CTASection, {})]
    }), /* @__PURE__ */ jsx(Footer, {})]
  });
});
const route1 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: home,
  meta: meta$2
}, Symbol.toStringTag, { value: "Module" }));
function meta$1({}) {
  return [{
    title: "Documentation - VIGIL Security"
  }, {
    name: "description",
    content: "VIGIL documentation - Learn how to integrate security middleware into your Express.js applications."
  }];
}
const docs = UNSAFE_withComponentProps(function Docs() {
  const sections = [{
    title: "Getting Started",
    description: "Learn how to install and set up VIGIL in your project.",
    links: [{
      text: "Installation",
      href: "#installation"
    }, {
      text: "Quick Start",
      href: "#quick-start"
    }, {
      text: "Configuration",
      href: "#configuration"
    }]
  }, {
    title: "Security Modules",
    description: "Detailed documentation for each security module.",
    links: [{
      text: "Rate Limiting",
      href: "#rate-limiting"
    }, {
      text: "Bot Detection",
      href: "#bot-detection"
    }, {
      text: "SQL Injection Guard",
      href: "#sql-injection"
    }, {
      text: "Email Verification",
      href: "#email-verification"
    }, {
      text: "Request Monitoring",
      href: "#monitoring"
    }, {
      text: "Policy Enforcement",
      href: "#policy"
    }]
  }, {
    title: "API Reference",
    description: "Complete API documentation for VIGIL.",
    links: [{
      text: "vigil() Function",
      href: "#vigil-function"
    }, {
      text: "Configuration Options",
      href: "#config-options"
    }, {
      text: "Middleware Options",
      href: "#middleware"
    }, {
      text: "Response Handling",
      href: "#responses"
    }]
  }, {
    title: "Advanced",
    description: "Advanced usage patterns and customization.",
    links: [{
      text: "Custom Rules",
      href: "#custom-rules"
    }, {
      text: "Logging",
      href: "#logging"
    }, {
      text: "Testing",
      href: "#testing"
    }, {
      text: "Performance",
      href: "#performance"
    }]
  }];
  return /* @__PURE__ */ jsxs(Fragment, {
    children: [/* @__PURE__ */ jsx(Navbar, {}), /* @__PURE__ */ jsxs("main", {
      style: {
        minHeight: "80vh",
        backgroundColor: "var(--color-background)"
      },
      children: [/* @__PURE__ */ jsx("section", {
        style: {
          padding: "80px 20px",
          borderBottom: "3px solid var(--color-border)"
        },
        children: /* @__PURE__ */ jsxs("div", {
          className: "container",
          children: [/* @__PURE__ */ jsx("h1", {
            className: "text-heading-xl",
            style: {
              marginBottom: "1rem"
            },
            children: "Documentation"
          }), /* @__PURE__ */ jsx("p", {
            className: "text-body-lg",
            style: {
              color: "#666",
              maxWidth: "600px"
            },
            children: "Everything you need to integrate VIGIL security middleware into your Express.js applications."
          })]
        })
      }), /* @__PURE__ */ jsx("section", {
        style: {
          padding: "60px 20px"
        },
        children: /* @__PURE__ */ jsxs("div", {
          className: "container",
          children: [/* @__PURE__ */ jsx("div", {
            style: {
              display: "grid",
              gridTemplateColumns: "repeat(2, 1fr)",
              gap: "2rem"
            },
            children: sections.map((section, index) => /* @__PURE__ */ jsxs("div", {
              className: "brutalist-card",
              children: [/* @__PURE__ */ jsx("h2", {
                style: {
                  fontSize: "1.25rem",
                  fontWeight: 700,
                  marginBottom: "0.75rem"
                },
                children: section.title
              }), /* @__PURE__ */ jsx("p", {
                style: {
                  color: "#666",
                  marginBottom: "1rem",
                  fontSize: "0.875rem"
                },
                children: section.description
              }), /* @__PURE__ */ jsx("ul", {
                style: {
                  listStyle: "none",
                  padding: 0,
                  margin: 0
                },
                children: section.links.map((link, idx) => /* @__PURE__ */ jsx("li", {
                  style: {
                    marginBottom: "0.5rem"
                  },
                  children: /* @__PURE__ */ jsxs("a", {
                    href: link.href,
                    style: {
                      color: "var(--color-primary-blue)",
                      textDecoration: "none",
                      fontWeight: 600,
                      fontSize: "0.875rem"
                    },
                    children: ["→ ", link.text]
                  })
                }, idx))
              })]
            }, index))
          }), /* @__PURE__ */ jsxs("div", {
            style: {
              marginTop: "4rem"
            },
            children: [/* @__PURE__ */ jsx("h2", {
              style: {
                fontSize: "1.5rem",
                fontWeight: 700,
                marginBottom: "1rem"
              },
              children: "Quick Example"
            }), /* @__PURE__ */ jsx("div", {
              className: "code-block",
              children: `import express from 'express';
import { vigil } from 'vigil-security';

const app = express();

// Add VIGIL middleware with custom configuration
app.use(vigil({
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per window
  },
  botDetection: {
    enabled: true,
    strictMode: true
  },
  sqlGuard: {
    enabled: true,
    logAttacks: true
  }
}));

// Your routes
app.get('/api/data', (req, res) => {
  res.json({ data: 'Secure response' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`
            })]
          })]
        })
      })]
    }), /* @__PURE__ */ jsx(Footer, {})]
  });
});
const route2 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: docs,
  meta: meta$1
}, Symbol.toStringTag, { value: "Module" }));
function meta({}) {
  return [{
    title: "About - VIGIL Security"
  }, {
    name: "description",
    content: "Learn about VIGIL Security - the security middleware for modern web applications."
  }];
}
const about = UNSAFE_withComponentProps(function About() {
  return /* @__PURE__ */ jsxs(Fragment, {
    children: [/* @__PURE__ */ jsx(Navbar, {}), /* @__PURE__ */ jsxs("main", {
      style: {
        minHeight: "80vh",
        backgroundColor: "var(--color-background)"
      },
      children: [/* @__PURE__ */ jsx("section", {
        style: {
          padding: "80px 20px",
          borderBottom: "3px solid var(--color-border)"
        },
        children: /* @__PURE__ */ jsxs("div", {
          className: "container",
          children: [/* @__PURE__ */ jsx("h1", {
            className: "text-heading-xl",
            style: {
              marginBottom: "1rem"
            },
            children: "About VIGIL"
          }), /* @__PURE__ */ jsx("p", {
            className: "text-body-lg",
            style: {
              color: "#666",
              maxWidth: "700px"
            },
            children: "VIGIL is an open-source security middleware designed to protect modern web applications from common security threats with minimal configuration."
          })]
        })
      }), /* @__PURE__ */ jsx("section", {
        style: {
          padding: "60px 20px"
        },
        children: /* @__PURE__ */ jsxs("div", {
          className: "container",
          children: [/* @__PURE__ */ jsxs("div", {
            style: {
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "3rem"
            },
            children: [/* @__PURE__ */ jsxs("div", {
              children: [/* @__PURE__ */ jsx("h2", {
                style: {
                  fontSize: "1.5rem",
                  fontWeight: 700,
                  marginBottom: "1rem"
                },
                children: "Our Mission"
              }), /* @__PURE__ */ jsx("p", {
                style: {
                  color: "#666",
                  lineHeight: 1.8,
                  marginBottom: "1.5rem"
                },
                children: "We believe security should be accessible to every developer. Too often, security is treated as an afterthought or requires expensive enterprise solutions. VIGIL aims to change that by providing enterprise-grade security as a simple, free-to-use middleware."
              }), /* @__PURE__ */ jsx("p", {
                style: {
                  color: "#666",
                  lineHeight: 1.8
                },
                children: "Born from the challenges of AI-assisted development, VIGIL addresses the security gap created by rapid prototyping and fast iteration cycles. We're here to ensure speed doesn't come at the cost of security."
              })]
            }), /* @__PURE__ */ jsxs("div", {
              children: [/* @__PURE__ */ jsx("h2", {
                style: {
                  fontSize: "1.5rem",
                  fontWeight: 700,
                  marginBottom: "1rem"
                },
                children: "Our Values"
              }), /* @__PURE__ */ jsxs("div", {
                style: {
                  display: "flex",
                  flexDirection: "column",
                  gap: "1rem"
                },
                children: [/* @__PURE__ */ jsxs("div", {
                  className: "brutalist-card-blue",
                  style: {
                    padding: "1rem"
                  },
                  children: [/* @__PURE__ */ jsx("h3", {
                    style: {
                      fontWeight: 700,
                      marginBottom: "0.5rem"
                    },
                    children: "Developer First"
                  }), /* @__PURE__ */ jsx("p", {
                    style: {
                      color: "#666",
                      fontSize: "0.875rem"
                    },
                    children: "Every decision we make starts with the developer experience. Simple APIs, clear documentation, and intuitive design."
                  })]
                }), /* @__PURE__ */ jsxs("div", {
                  className: "brutalist-card-blue",
                  style: {
                    padding: "1rem"
                  },
                  children: [/* @__PURE__ */ jsx("h3", {
                    style: {
                      fontWeight: 700,
                      marginBottom: "0.5rem"
                    },
                    children: "Open Source"
                  }), /* @__PURE__ */ jsx("p", {
                    style: {
                      color: "#666",
                      fontSize: "0.875rem"
                    },
                    children: "Security should be transparent and auditable. VIGIL is open source with permissive licensing."
                  })]
                }), /* @__PURE__ */ jsxs("div", {
                  className: "brutalist-card-blue",
                  style: {
                    padding: "1rem"
                  },
                  children: [/* @__PURE__ */ jsx("h3", {
                    style: {
                      fontWeight: 700,
                      marginBottom: "0.5rem"
                    },
                    children: "Continuous Improvement"
                  }), /* @__PURE__ */ jsx("p", {
                    style: {
                      color: "#666",
                      fontSize: "0.875rem"
                    },
                    children: "Security threats evolve daily. We're committed to staying ahead and providing regular updates."
                  })]
                })]
              })]
            })]
          }), /* @__PURE__ */ jsxs("div", {
            style: {
              marginTop: "4rem",
              paddingTop: "3rem",
              borderTop: "3px solid var(--color-border)"
            },
            children: [/* @__PURE__ */ jsx("h2", {
              style: {
                fontSize: "1.5rem",
                fontWeight: 700,
                marginBottom: "1.5rem"
              },
              children: "Get Involved"
            }), /* @__PURE__ */ jsxs("div", {
              style: {
                display: "grid",
                gridTemplateColumns: "repeat(3, 1fr)",
                gap: "2rem"
              },
              children: [/* @__PURE__ */ jsxs("div", {
                className: "brutalist-card",
                style: {
                  textAlign: "center"
                },
                children: [/* @__PURE__ */ jsx("div", {
                  style: {
                    fontSize: "2rem",
                    marginBottom: "1rem"
                  },
                  children: "🐙"
                }), /* @__PURE__ */ jsx("h3", {
                  style: {
                    fontWeight: 700,
                    marginBottom: "0.5rem"
                  },
                  children: "GitHub"
                }), /* @__PURE__ */ jsx("p", {
                  style: {
                    color: "#666",
                    fontSize: "0.875rem"
                  },
                  children: "Star us, report issues, and contribute to the codebase."
                }), /* @__PURE__ */ jsx("a", {
                  href: "https://github.com",
                  style: {
                    color: "var(--color-primary-blue)",
                    fontWeight: 600,
                    fontSize: "0.875rem"
                  },
                  children: "github.com/vigil-security →"
                })]
              }), /* @__PURE__ */ jsxs("div", {
                className: "brutalist-card",
                style: {
                  textAlign: "center"
                },
                children: [/* @__PURE__ */ jsx("div", {
                  style: {
                    fontSize: "2rem",
                    marginBottom: "1rem"
                  },
                  children: "💬"
                }), /* @__PURE__ */ jsx("h3", {
                  style: {
                    fontWeight: 700,
                    marginBottom: "0.5rem"
                  },
                  children: "Discord"
                }), /* @__PURE__ */ jsx("p", {
                  style: {
                    color: "#666",
                    fontSize: "0.875rem"
                  },
                  children: "Join our community to ask questions and share ideas."
                }), /* @__PURE__ */ jsx("a", {
                  href: "#",
                  style: {
                    color: "var(--color-primary-blue)",
                    fontWeight: 600,
                    fontSize: "0.875rem"
                  },
                  children: "Join Discord →"
                })]
              }), /* @__PURE__ */ jsxs("div", {
                className: "brutalist-card",
                style: {
                  textAlign: "center"
                },
                children: [/* @__PURE__ */ jsx("div", {
                  style: {
                    fontSize: "2rem",
                    marginBottom: "1rem"
                  },
                  children: "🐦"
                }), /* @__PURE__ */ jsx("h3", {
                  style: {
                    fontWeight: 700,
                    marginBottom: "0.5rem"
                  },
                  children: "Twitter"
                }), /* @__PURE__ */ jsx("p", {
                  style: {
                    color: "#666",
                    fontSize: "0.875rem"
                  },
                  children: "Follow us for updates, security tips, and news."
                }), /* @__PURE__ */ jsx("a", {
                  href: "#",
                  style: {
                    color: "var(--color-primary-blue)",
                    fontWeight: 600,
                    fontSize: "0.875rem"
                  },
                  children: "Follow @vigil →"
                })]
              })]
            })]
          })]
        })
      })]
    }), /* @__PURE__ */ jsx(Footer, {})]
  });
});
const route3 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: about,
  meta
}, Symbol.toStringTag, { value: "Module" }));
const serverManifest = { "entry": { "module": "/assets/entry.client-B2gJlt0w.js", "imports": ["/assets/chunk-EPOLDU6W-DF41ubp-.js"], "css": [] }, "routes": { "root": { "id": "root", "parentId": void 0, "path": "", "index": void 0, "caseSensitive": void 0, "hasAction": false, "hasLoader": false, "hasClientAction": false, "hasClientLoader": false, "hasClientMiddleware": false, "hasErrorBoundary": true, "module": "/assets/root-Cd78W6m7.js", "imports": ["/assets/chunk-EPOLDU6W-DF41ubp-.js"], "css": ["/assets/root-C1Nqe1Am.css"], "clientActionModule": void 0, "clientLoaderModule": void 0, "clientMiddlewareModule": void 0, "hydrateFallbackModule": void 0 }, "routes/home": { "id": "routes/home", "parentId": "root", "path": void 0, "index": true, "caseSensitive": void 0, "hasAction": false, "hasLoader": false, "hasClientAction": false, "hasClientLoader": false, "hasClientMiddleware": false, "hasErrorBoundary": false, "module": "/assets/home-BhgN2_DW.js", "imports": ["/assets/chunk-EPOLDU6W-DF41ubp-.js", "/assets/Footer-BKgmljf6.js"], "css": [], "clientActionModule": void 0, "clientLoaderModule": void 0, "clientMiddlewareModule": void 0, "hydrateFallbackModule": void 0 }, "routes/docs": { "id": "routes/docs", "parentId": "root", "path": "docs", "index": void 0, "caseSensitive": void 0, "hasAction": false, "hasLoader": false, "hasClientAction": false, "hasClientLoader": false, "hasClientMiddleware": false, "hasErrorBoundary": false, "module": "/assets/docs-DdLm7-cV.js", "imports": ["/assets/chunk-EPOLDU6W-DF41ubp-.js", "/assets/Footer-BKgmljf6.js"], "css": [], "clientActionModule": void 0, "clientLoaderModule": void 0, "clientMiddlewareModule": void 0, "hydrateFallbackModule": void 0 }, "routes/about": { "id": "routes/about", "parentId": "root", "path": "about", "index": void 0, "caseSensitive": void 0, "hasAction": false, "hasLoader": false, "hasClientAction": false, "hasClientLoader": false, "hasClientMiddleware": false, "hasErrorBoundary": false, "module": "/assets/about-BSHlFEBD.js", "imports": ["/assets/chunk-EPOLDU6W-DF41ubp-.js", "/assets/Footer-BKgmljf6.js"], "css": [], "clientActionModule": void 0, "clientLoaderModule": void 0, "clientMiddlewareModule": void 0, "hydrateFallbackModule": void 0 } }, "url": "/assets/manifest-1e4afd7a.js", "version": "1e4afd7a", "sri": void 0 };
const assetsBuildDirectory = "build/client";
const basename = "/";
const future = { "unstable_optimizeDeps": false, "unstable_subResourceIntegrity": false, "unstable_trailingSlashAwareDataRequests": false, "v8_middleware": false, "v8_splitRouteModules": false, "v8_viteEnvironmentApi": false };
const ssr = true;
const isSpaMode = false;
const prerender = [];
const routeDiscovery = { "mode": "lazy", "manifestPath": "/__manifest" };
const publicPath = "/";
const entry = { module: entryServer };
const routes = {
  "root": {
    id: "root",
    parentId: void 0,
    path: "",
    index: void 0,
    caseSensitive: void 0,
    module: route0
  },
  "routes/home": {
    id: "routes/home",
    parentId: "root",
    path: void 0,
    index: true,
    caseSensitive: void 0,
    module: route1
  },
  "routes/docs": {
    id: "routes/docs",
    parentId: "root",
    path: "docs",
    index: void 0,
    caseSensitive: void 0,
    module: route2
  },
  "routes/about": {
    id: "routes/about",
    parentId: "root",
    path: "about",
    index: void 0,
    caseSensitive: void 0,
    module: route3
  }
};
const allowedActionOrigins = false;
export {
  allowedActionOrigins,
  serverManifest as assets,
  assetsBuildDirectory,
  basename,
  entry,
  future,
  isSpaMode,
  prerender,
  publicPath,
  routeDiscovery,
  routes,
  ssr
};
