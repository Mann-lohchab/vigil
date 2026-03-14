import { Link } from "react-router";
import { ShieldIcon, BotIcon, LockIcon, EmailIcon, CheckIcon } from "./Icons";

export function Hero() {
  return (
    <section className="section" style={{ backgroundColor: 'var(--color-light-background)', paddingTop: '100px', paddingBottom: '100px' }}>
      <div className="container">
        <div className="two-column">
          {/* Left Column - Content */}
          <div>
            <div className="badge mb-4">Security Middleware</div>
            <h1 className="text-heading-xl" style={{ marginBottom: '1.5rem', color: 'var(--color-text)' }}>
              Security Middleware for Modern Web Applications
            </h1>
            <p className="text-body-lg" style={{ marginBottom: '2rem', color: '#444', maxWidth: '540px' }}>
              VIGIL protects your Express.js applications automatically. 
              Enterprise-grade security with zero configuration required. 
              Block bots, prevent SQL injection, rate limit abuse, and verify emails — all in one package.
            </p>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <Link to="/docs" className="btn-primary">
                Get Started
              </Link>
              <Link to="/docs" className="btn-secondary">
                View Docs
              </Link>
            </div>
          </div>
          
          {/* Right Column - Technical Diagram */}
          <div className="brutalist-card" style={{ backgroundColor: 'white' }}>
            <h3 style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '1rem', color: '#666', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Request Flow Through VIGIL Security Layer
            </h3>
            
            {/* Diagram */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {/* HTTP Request */}
              <div style={{ 
                padding: '1rem', 
                border: '3px solid var(--color-border)', 
                backgroundColor: '#f5f5f5',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.75rem'
              }}>
                <span style={{ color: '#666' }}>→ HTTP Request</span>
              </div>
              
              {/* Arrow */}
              <div style={{ textAlign: 'center', color: 'var(--color-primary-blue)', fontWeight: 800 }}>↓</div>
              
              {/* Rate Limiting */}
              <div style={{ 
                padding: '0.875rem', 
                border: '3px solid var(--color-primary-blue)', 
                backgroundColor: 'var(--color-light-background)',
                boxShadow: '4px 4px 0px var(--color-primary-blue)',
                fontWeight: 600,
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                <ShieldIcon size={18} />
                Rate Limiting
                <span style={{ display: 'block', fontSize: '0.7rem', color: '#666', marginTop: '0.25rem' }}>Limits requests per IP</span>
              </div>
              
              {/* Arrow */}
              <div style={{ textAlign: 'center', color: 'var(--color-primary-blue)', fontWeight: 800 }}>↓</div>
              
              {/* Bot Detection */}
              <div style={{ 
                padding: '0.875rem', 
                border: '3px solid var(--color-primary-blue)', 
                backgroundColor: 'var(--color-light-background)',
                boxShadow: '4px 4px 0px var(--color-primary-blue)',
                fontWeight: 600,
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                <BotIcon size={18} />
                Bot Detection
                <span style={{ display: 'block', fontSize: '0.7rem', color: '#666', marginTop: '0.25rem' }}>Identifies malicious bots</span>
              </div>
              
              {/* Arrow */}
              <div style={{ textAlign: 'center', color: 'var(--color-primary-blue)', fontWeight: 800 }}>↓</div>
              
              {/* SQL Injection Guard */}
              <div style={{ 
                padding: '0.875rem', 
                border: '3px solid var(--color-primary-blue)', 
                backgroundColor: 'var(--color-light-background)',
                boxShadow: '4px 4px 0px var(--color-primary-blue)',
                fontWeight: 600,
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                <LockIcon size={18} />
                SQL Injection Guard
                <span style={{ display: 'block', fontSize: '0.7rem', color: '#666', marginTop: '0.25rem' }}>Blocks SQL injection attacks</span>
              </div>
              
              {/* Arrow */}
              <div style={{ textAlign: 'center', color: 'var(--color-primary-blue)', fontWeight: 800 }}>↓</div>
              
              {/* Email Verification */}
              <div style={{ 
                padding: '0.875rem', 
                border: '3px solid var(--color-primary-blue)', 
                backgroundColor: 'var(--color-light-background)',
                boxShadow: '4px 4px 0px var(--color-primary-blue)',
                fontWeight: 600,
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                <EmailIcon size={18} />
                Email Verification
                <span style={{ display: 'block', fontSize: '0.7rem', color: '#666', marginTop: '0.25rem' }}>Verifies email addresses</span>
              </div>
              
              {/* Arrow */}
              <div style={{ textAlign: 'center', color: '#22c55e', fontWeight: 800 }}>↓</div>
              
              {/* Application Logic */}
              <div style={{ 
                padding: '1rem', 
                border: '3px solid #22c55e', 
                backgroundColor: '#f0fdf4',
                boxShadow: '4px 4px 0px #22c55e',
                fontWeight: 600,
                fontSize: '0.875rem',
                textAlign: 'center',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}>
                <CheckIcon size={16} style={{ color: '#22c55e' }} />
                Clean Request → Your App
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
