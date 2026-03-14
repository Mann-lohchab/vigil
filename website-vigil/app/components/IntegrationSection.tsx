import { CheckIcon } from "./Icons";

export function IntegrationSection() {
  return (
    <section className="section" style={{ backgroundColor: 'var(--color-background)' }}>
      <div className="container">
        <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
          <h2 className="text-heading-lg" style={{ marginBottom: '1rem' }}>
            Simple Integration
          </h2>
          <p className="text-body-lg" style={{ color: '#666', maxWidth: '600px', margin: '0 auto' }}>
            Add enterprise-grade security to your Express.js app in under 2 minutes.
          </p>
        </div>
        
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '3rem', alignItems: 'start' }}>
          {/* npm install */}
          <div>
            <div className="brutalist-card">
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: '#666', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                Step 1: Install
              </h3>
              <div className="code-block" style={{ padding: '1rem' }}>
                <span style={{ color: '#6272a4' }}>$</span> npm install vigil-security
              </div>
            </div>
            
            <div className="brutalist-card" style={{ marginTop: '1.5rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: '#666', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                Step 2: Configure
              </h3>
              <div className="code-block">
{`import express from 'express';
import { vigil } from 'vigil-security';

const app = express();

// Add VIGIL middleware
app.use(vigil());

// Your routes
app.get('/', (req, res) => {
  res.json({ message: 'Secure!' });
});

app.listen(3000);`}
              </div>
            </div>
          </div>
          
          {/* Code Explanation */}
          <div>
            <h3 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckIcon size={24} style={{ color: '#22c55e' }} />
              That's It!
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div className="brutalist-card-blue" style={{ padding: '1.25rem' }}>
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
                      The above code enables all security modules with sensible defaults. 
                      Your app is protected immediately.
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="brutalist-card-blue" style={{ padding: '1.25rem' }}>
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
                    <h4 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Customize as Needed</h4>
                    <p style={{ color: '#666', lineHeight: 1.6, fontSize: '0.875rem' }}>
                      Pass options to enable specific modules or override defaults:
                    </p>
                    <div className="code-block" style={{ marginTop: '0.75rem', padding: '0.75rem', fontSize: '0.75rem' }}>
{`vigil({
  rateLimit: { windowMs: 60000, max: 100 },
  botDetection: { enabled: true },
  sqlGuard: { enabled: true },
  emailVerification: { enabled: false }
})`}
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="brutalist-card-blue" style={{ padding: '1.25rem' }}>
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
                    <h4 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>TypeScript Support</h4>
                    <p style={{ color: '#666', lineHeight: 1.6, fontSize: '0.875rem' }}>
                      Full TypeScript support with automatic type inference. 
                      IntelliSense for all configuration options.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
