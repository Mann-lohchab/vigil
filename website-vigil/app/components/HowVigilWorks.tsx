import { GlobeIcon, SearchIcon, ShieldIcon, ScaleIcon, CheckIcon, XIcon, WarningIcon } from "./Icons";

export function HowVigilWorks() {
  return (
    <section className="section" style={{ backgroundColor: 'var(--color-light-background)' }}>
      <div className="container">
        <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
          <h2 className="text-heading-lg" style={{ marginBottom: '1rem' }}>
            How VIGIL Works
          </h2>
          <p className="text-body-lg" style={{ color: '#666', maxWidth: '600px', margin: '0 auto' }}>
            VIGIL sits between the HTTP request and your application logic, providing 
            comprehensive threat detection and policy enforcement.
          </p>
        </div>
        
        {/* Middleware Architecture Diagram */}
        <div className="brutalist-card" style={{ maxWidth: '900px', margin: '0 auto', padding: '2rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '2rem', color: '#666', textTransform: 'uppercase', letterSpacing: '0.1em', textAlign: 'center' }}>
            Middleware Architecture
          </h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {/* Row 1: Request Entry */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div style={{ 
                flex: 1, 
                padding: '1.5rem', 
                backgroundColor: '#f5f5f5', 
                border: '3px solid var(--color-border)',
                textAlign: 'center',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}>
                <GlobeIcon size={20} />
                HTTP Request
              </div>
              <div style={{ color: 'var(--color-primary-blue)', fontSize: '1.5rem', fontWeight: 800 }}>→</div>
              <div style={{ 
                flex: 1, 
                padding: '1.5rem', 
                backgroundColor: 'var(--color-primary-blue)', 
                border: '3px solid var(--color-border)',
                color: 'white',
                textAlign: 'center',
                fontWeight: 700,
                boxShadow: '4px 4px 0px black'
              }}>
                VIGIL Security Layer
              </div>
            </div>
            
            {/* Arrow down */}
            <div style={{ textAlign: 'center', fontSize: '1.5rem', color: 'var(--color-primary-blue)', fontWeight: 800 }}>
              ↓
            </div>
            
            {/* Row 2: Processing Steps */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
              <div style={{ 
                padding: '1.25rem', 
                backgroundColor: 'white', 
                border: '3px solid var(--color-border)',
                textAlign: 'center',
                boxShadow: '4px 4px 0px black'
              }}>
                <SearchIcon size={24} style={{ marginBottom: '0.5rem' }} />
                <div style={{ fontWeight: 700, fontSize: '0.875rem' }}>1. Request Inspection</div>
                <div style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.5rem' }}>
                  Analyze headers, body, and parameters
                </div>
              </div>
              
              <div style={{ 
                padding: '1.25rem', 
                backgroundColor: 'white', 
                border: '3px solid var(--color-border)',
                textAlign: 'center',
                boxShadow: '4px 4px 0px black'
              }}>
                <ShieldIcon size={24} style={{ marginBottom: '0.5rem' }} />
                <div style={{ fontWeight: 700, fontSize: '0.875rem' }}>2. Threat Detection</div>
                <div style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.5rem' }}>
                  Run security checks against rules
                </div>
              </div>
              
              <div style={{ 
                padding: '1.25rem', 
                backgroundColor: 'white', 
                border: '3px solid var(--color-border)',
                textAlign: 'center',
                boxShadow: '4px 4px 0px black'
              }}>
                <ScaleIcon size={24} style={{ marginBottom: '0.5rem' }} />
                <div style={{ fontWeight: 700, fontSize: '0.875rem' }}>3. Policy Enforcement</div>
                <div style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.5rem' }}>
                  Allow, block, or challenge request
                </div>
              </div>
            </div>
            
            {/* Arrow down */}
            <div style={{ textAlign: 'center', fontSize: '1.5rem', color: '#22c55e', fontWeight: 800 }}>
              ↓
            </div>
            
            {/* Row 3: Outcome */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div style={{ 
                flex: 1, 
                padding: '1rem', 
                backgroundColor: '#f0fdf4', 
                border: '3px solid #22c55e',
                textAlign: 'center',
                fontWeight: 600,
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}>
                <CheckIcon size={16} style={{ color: '#22c55e' }} />
                Pass → Your Express App
              </div>
              <div style={{ color: '#dc2626', fontSize: '1.5rem', fontWeight: 800 }}>|</div>
              <div style={{ 
                flex: 1, 
                padding: '1rem', 
                backgroundColor: '#fef2f2', 
                border: '3px solid #dc2626',
                textAlign: 'center',
                fontWeight: 600,
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}>
                <XIcon size={16} style={{ color: '#dc2626' }} />
                Block → 403 Forbidden
              </div>
              <div style={{ color: '#f59e0b', fontSize: '1.5rem', fontWeight: 800 }}>|</div>
              <div style={{ 
                flex: 1, 
                padding: '1rem', 
                backgroundColor: '#fffbeb', 
                border: '3px solid #f59e0b',
                textAlign: 'center',
                fontWeight: 600,
                fontSize: '0.875rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}>
                <WarningIcon size={16} style={{ color: '#f59e0b' }} />
                Challenge → CAPTCHA
              </div>
            </div>
          </div>
        </div>
        
        {/* Key Points */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '2rem', marginTop: '3rem', maxWidth: '900px', margin: '3rem auto 0' }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div style={{ 
              width: '32px', 
              height: '32px', 
              backgroundColor: 'var(--color-primary-blue)', 
              color: 'white',
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              fontWeight: 800,
              flexShrink: 0
            }}>
              1
            </div>
            <div>
              <h4 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Zero Configuration</h4>
              <p style={{ color: '#666', lineHeight: 1.6, fontSize: '0.875rem' }}>
                VIGIL works out of the box with sensible defaults. Add the middleware and you're protected immediately.
              </p>
            </div>
          </div>
          
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div style={{ 
              width: '32px', 
              height: '32px', 
              backgroundColor: 'var(--color-primary-blue)', 
              color: 'white',
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              fontWeight: 800,
              flexShrink: 0
            }}>
              2
            </div>
            <div>
              <h4 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Modular Architecture</h4>
              <p style={{ color: '#666', lineHeight: 1.6, fontSize: '0.875rem' }}>
                Enable or disable specific security modules based on your application's needs.
              </p>
            </div>
          </div>
          
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div style={{ 
              width: '32px', 
              height: '32px', 
              backgroundColor: 'var(--color-primary-blue)', 
              color: 'white',
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              fontWeight: 800,
              flexShrink: 0
            }}>
              3
            </div>
            <div>
              <h4 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Request Context</h4>
              <p style={{ color: '#666', lineHeight: 1.6, fontSize: '0.875rem' }}>
                Unlike WAFs, VIGIL understands your application's specific context and can make smarter decisions.
              </p>
            </div>
          </div>
          
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
            <div style={{ 
              width: '32px', 
              height: '32px', 
              backgroundColor: 'var(--color-primary-blue)', 
              color: 'white',
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              fontWeight: 800,
              flexShrink: 0
            }}>
              4
            </div>
            <div>
              <h4 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Developer Friendly</h4>
              <p style={{ color: '#666', lineHeight: 1.6, fontSize: '0.875rem' }}>
                Clear error messages, detailed logs, and intuitive APIs make debugging straightforward.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
