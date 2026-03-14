import { LightningIcon, BotIcon, LockIcon, EmailIcon, ChartIcon, GearIcon, CheckIcon } from "./Icons";

interface SecurityModule {
  icon: React.ReactNode;
  title: string;
  description: string;
  features: string[];
}

const securityModules: SecurityModule[] = [
  {
    icon: <LightningIcon size={28} />,
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
    icon: <BotIcon size={28} />,
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
    icon: <LockIcon size={28} />,
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
    icon: <EmailIcon size={28} />,
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
    icon: <ChartIcon size={28} />,
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
    icon: <GearIcon size={28} />,
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

export function FeatureGrid() {
  return (
    <section className="section" style={{ backgroundColor: 'var(--color-background)' }}>
      <div className="container">
        <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
          <h2 className="text-heading-lg" style={{ marginBottom: '1rem' }}>
            Security Modules
          </h2>
          <p className="text-body-lg" style={{ color: '#666', maxWidth: '600px', margin: '0 auto' }}>
            Six powerful security modules working together to protect your application 
            from modern threats.
          </p>
        </div>
        
        <div className="grid-3">
          {securityModules.map((module, index) => (
            <div key={index} className="brutalist-card-blue" style={{ height: '100%' }}>
              <div style={{ 
                width: '56px', 
                height: '56px', 
                backgroundColor: 'var(--color-primary-blue)', 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center',
                border: '3px solid var(--color-border)',
                marginBottom: '1.25rem',
                color: 'white'
              }}>
                {module.icon}
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
                {module.title}
              </h3>
              <p style={{ color: '#666', lineHeight: 1.6, marginBottom: '1rem', fontSize: '0.875rem' }}>
                {module.description}
              </p>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                {module.features.map((feature, idx) => (
                  <li key={idx} style={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: '0.5rem',
                    padding: '0.375rem 0',
                    fontSize: '0.8rem',
                    color: '#444'
                  }}>
                    <CheckIcon size={14} style={{ color: 'var(--color-primary-blue)' }} />
                    {feature}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
