import { LightningIcon, WarningIcon, UnlockIcon, WrenchIcon, BuildingIcon, DollarIcon } from "./Icons";

export function ProblemSection() {
  return (
    <section className="section" style={{ backgroundColor: 'var(--color-background)' }}>
      <div className="container">
        <div style={{ maxWidth: '800px', margin: '0 auto', textAlign: 'center' }}>
          <h2 className="text-heading-lg" style={{ marginBottom: '1rem' }}>
            The Security Gap in AI-Assisted Development
          </h2>
          <p className="text-body-lg" style={{ color: '#666', marginBottom: '3rem' }}>
            AI coding assistants accelerate development but often skip critical security review. 
            This creates a new class of vulnerabilities in production applications.
          </p>
        </div>
        
        <div className="grid-3">
          {/* Card 1: Rapid Prototyping */}
          <div className="brutalist-card">
            <div style={{ 
              width: '48px', 
              height: '48px', 
              backgroundColor: 'var(--color-primary-blue)', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              border: '3px solid var(--color-border)',
              marginBottom: '1rem',
              color: 'white'
            }}>
              <LightningIcon size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Rapid Prototyping
            </h3>
            <p style={{ color: '#666', lineHeight: 1.6 }}>
              AI tools generate code at lightning speed, but security considerations are often 
              overlooked in the quest for faster iteration cycles.
            </p>
          </div>
          
          {/* Card 2: Missing Security Reviews */}
          <div className="brutalist-card">
            <div style={{ 
              width: '48px', 
              height: '48px', 
              backgroundColor: '#dc2626', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              border: '3px solid var(--color-border)',
              marginBottom: '1rem',
              color: 'white'
            }}>
              <WarningIcon size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Missing Security Reviews
            </h3>
            <p style={{ color: '#666', lineHeight: 1.6 }}>
              Traditional security workflows can't keep up with AI-accelerated development. 
              Code reaches production without proper security auditing.
            </p>
          </div>
          
          {/* Card 3: Common Vulnerabilities */}
          <div className="brutalist-card">
            <div style={{ 
              width: '48px', 
              height: '48px', 
              backgroundColor: '#ea580c', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              border: '3px solid var(--color-border)',
              marginBottom: '1rem',
              color: 'white'
            }}>
              <UnlockIcon size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Common Vulnerabilities
            </h3>
            <p style={{ color: '#666', lineHeight: 1.6 }}>
              SQL injection, XSS, CSRF, and rate limiting vulnerabilities become 
              commonplace when security is treated as an afterthought.
            </p>
          </div>
          
          {/* Card 4: Complex Tooling */}
          <div className="brutalist-card">
            <div style={{ 
              width: '48px', 
              height: '48px', 
              backgroundColor: '#7c3aed', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              border: '3px solid var(--color-border)',
              marginBottom: '1rem',
              color: 'white'
            }}>
              <WrenchIcon size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Complex Security Tooling
            </h3>
            <p style={{ color: '#666', lineHeight: 1.6 }}>
              Existing security solutions require steep learning curves, multiple 
              integrations, and significant configuration overhead.
            </p>
          </div>
          
          {/* Card 5: Infrastructure vs Application */}
          <div className="brutalist-card">
            <div style={{ 
              width: '48px', 
              height: '48px', 
              backgroundColor: '#0891b2', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              border: '3px solid var(--color-border)',
              marginBottom: '1rem',
              color: 'white'
            }}>
              <BuildingIcon size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Infrastructure vs Application
            </h3>
            <p style={{ color: '#666', lineHeight: 1.6 }}>
              WAFs and network firewalls operate at the infrastructure layer, 
              lacking context about application-specific threats.
            </p>
          </div>
          
          {/* Card 6: Resource Drain */}
          <div className="brutalist-card">
            <div style={{ 
              width: '48px', 
              height: '48px', 
              backgroundColor: '#be185d', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              border: '3px solid var(--color-border)',
              marginBottom: '1rem',
              color: 'white'
            }}>
              <DollarIcon size={24} />
            </div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.75rem' }}>
              Resource Drain
            </h3>
            <p style={{ color: '#666', lineHeight: 1.6 }}>
              Building custom security solutions drains development resources 
              and distracts from core product development.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
