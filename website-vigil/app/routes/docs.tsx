import type { Route } from "./+types/docs";
import { Navbar } from "../components/Navbar";
import { Footer } from "../components/Footer";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "Documentation - VIGIL Security" },
    { name: "description", content: "VIGIL documentation - Learn how to integrate security middleware into your Express.js applications." },
  ];
}

export default function Docs() {
  const sections = [
    {
      title: "Getting Started",
      description: "Learn how to install and set up VIGIL in your project.",
      links: [
        { text: "Installation", href: "#installation" },
        { text: "Quick Start", href: "#quick-start" },
        { text: "Configuration", href: "#configuration" },
      ]
    },
    {
      title: "Security Modules",
      description: "Detailed documentation for each security module.",
      links: [
        { text: "Rate Limiting", href: "#rate-limiting" },
        { text: "Bot Detection", href: "#bot-detection" },
        { text: "SQL Injection Guard", href: "#sql-injection" },
        { text: "Email Verification", href: "#email-verification" },
        { text: "Request Monitoring", href: "#monitoring" },
        { text: "Policy Enforcement", href: "#policy" },
      ]
    },
    {
      title: "API Reference",
      description: "Complete API documentation for VIGIL.",
      links: [
        { text: "vigil() Function", href: "#vigil-function" },
        { text: "Configuration Options", href: "#config-options" },
        { text: "Middleware Options", href: "#middleware" },
        { text: "Response Handling", href: "#responses" },
      ]
    },
    {
      title: "Advanced",
      description: "Advanced usage patterns and customization.",
      links: [
        { text: "Custom Rules", href: "#custom-rules" },
        { text: "Logging", href: "#logging" },
        { text: "Testing", href: "#testing" },
        { text: "Performance", href: "#performance" },
      ]
    },
  ];

  return (
    <>
      <Navbar />
      <main style={{ minHeight: '80vh', backgroundColor: 'var(--color-background)', paddingTop: '80px' }}>
        <section style={{ padding: '80px 20px', borderBottom: '3px solid var(--color-border)' }}>
          <div className="container">
            <h1 className="text-heading-xl" style={{ marginBottom: '1rem' }}>
              Documentation
            </h1>
            <p className="text-body-lg" style={{ color: '#666', maxWidth: '600px' }}>
              Everything you need to integrate VIGIL security middleware into your Express.js applications.
            </p>
          </div>
        </section>
        
        <section style={{ padding: '60px 20px' }}>
          <div className="container">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '2rem' }}>
              {sections.map((section, index) => (
                <div key={index} className="brutalist-card">
                  <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
                    {section.title}
                  </h2>
                  <p style={{ color: '#666', marginBottom: '1rem', fontSize: '0.875rem' }}>
                    {section.description}
                  </p>
                  <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    {section.links.map((link, idx) => (
                      <li key={idx} style={{ marginBottom: '0.5rem' }}>
                        <a 
                          href={link.href} 
                          style={{ 
                            color: 'var(--color-primary-blue)', 
                            textDecoration: 'none',
                            fontWeight: 600,
                            fontSize: '0.875rem'
                          }}
                        >
                          → {link.text}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
            
            {/* Quick Code Example */}
            <div style={{ marginTop: '4rem' }}>
              <h2 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '1rem' }}>
                Quick Example
              </h2>
              <div className="code-block">
{`import express from 'express';
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
});`}
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
