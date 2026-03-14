import { CheckIcon, XIcon } from "./Icons";

export function ArchitectureDiagram() {
  return (
    <section className="section" style={{ backgroundColor: 'var(--color-light-background)' }}>
      <div className="container">
        <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
          <h2 className="text-heading-lg" style={{ marginBottom: '1rem' }}>
            Architecture Comparison
          </h2>
          <p className="text-body-lg" style={{ color: '#666', maxWidth: '700px', margin: '0 auto' }}>
            See how VIGIL's application-layer security compares to traditional infrastructure solutions.
          </p>
        </div>
        
        {/* Comparison Table */}
        <div style={{ overflowX: 'auto', marginBottom: '3rem' }}>
          <table className="brutalist-table" style={{ minWidth: '800px' }}>
            <thead>
              <tr>
                <th style={{ width: '30%' }}>Feature</th>
                <th style={{ width: '23%', backgroundColor: '#666' }}>WAF</th>
                <th style={{ width: '23%', backgroundColor: '#666' }}>Network Firewall</th>
                <th style={{ width: '23%', backgroundColor: 'var(--color-primary-blue)' }}>VIGIL</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600 }}>Layer</td>
                <td>Network/Transport</td>
                <td>Network</td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600 }}>Application</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Request Context</td>
                <td style={{ color: '#666' }}>Limited</td>
                <td style={{ color: '#666' }}>None</td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600 }}>Full Access</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>SQL Injection Protection</td>
                <td style={{ color: '#666' }}>Basic patterns</td>
                <td style={{ color: '#666' }}>✕</td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600 }}><CheckIcon size={14} /> Advanced</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Bot Detection</td>
                <td style={{ color: '#666' }}>Limited</td>
                <td style={{ color: '#666' }}>✕</td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600 }}><CheckIcon size={14} /> Behavioral</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Rate Limiting</td>
                <td style={{ color: '#666' }}><CheckIcon size={14} /></td>
                <td style={{ color: '#666' }}><CheckIcon size={14} /></td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600 }}><CheckIcon size={14} /> Granular</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Email Verification</td>
                <td style={{ color: '#666' }}>✕</td>
                <td style={{ color: '#666' }}>✕</td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600 }}><CheckIcon size={14} /> Built-in</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Integration Effort</td>
                <td style={{ color: '#f59e0b' }}>High</td>
                <td style={{ color: '#f59e0b' }}>High</td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600, color: '#22c55e' }}>Low (2 lines)</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Developer Control</td>
                <td style={{ color: '#666' }}>Limited</td>
                <td style={{ color: '#666' }}>None</td>
                <td style={{ backgroundColor: '#dbeafe', fontWeight: 600 }}>Full</td>
              </tr>
            </tbody>
          </table>
        </div>
        
        {/* Visual Comparison */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '2rem', marginTop: '3rem' }}>
          {/* Traditional Tools */}
          <div className="brutalist-card" style={{ textAlign: 'center' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: '#666' }}>
              Traditional Tools
            </h3>
            <div style={{ 
              border: '3px dashed #999', 
              padding: '1.5rem', 
              marginBottom: '1rem',
              backgroundColor: '#f9f9f9'
            }}>
              <div style={{ fontSize: '0.75rem', color: '#666', marginBottom: '0.5rem' }}>INFRASTRUCTURE LAYER</div>
              <div style={{ fontWeight: 700, fontSize: '0.875rem' }}>WAF / Firewall</div>
            </div>
            <div style={{ 
              border: '3px dashed #999', 
              padding: '1.5rem',
              backgroundColor: '#f9f9f9',
              opacity: 0.5
            }}>
              <div style={{ fontSize: '0.75rem', color: '#666', marginBottom: '0.5rem' }}>APPLICATION LAYER</div>
              <div style={{ fontWeight: 700, fontSize: '0.875rem', color: '#999' }}>Your App</div>
            </div>
            <p style={{ fontSize: '0.8rem', color: '#666', marginTop: '1rem' }}>
              Operate at infrastructure layer with limited visibility into application context
            </p>
          </div>
          
          {/* Arrow */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '2rem', color: 'var(--color-primary-blue)' }}>
            →
          </div>
          
          {/* VIGIL */}
          <div className="brutalist-card" style={{ textAlign: 'center', borderColor: 'var(--color-primary-blue)' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: 'var(--color-primary-blue)' }}>
              VIGIL
            </h3>
            <div style={{ 
              border: '3px solid var(--color-primary-blue)', 
              padding: '1.5rem', 
              marginBottom: '1rem',
              backgroundColor: 'var(--color-light-background)',
              boxShadow: '4px 4px 0px var(--color-primary-blue)'
            }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--color-primary-blue)', marginBottom: '0.5rem' }}>APPLICATION LAYER</div>
              <div style={{ fontWeight: 700, fontSize: '0.875rem' }}>VIGIL Security</div>
            </div>
            <div style={{ 
              border: '3px solid #22c55e', 
              padding: '1.5rem',
              backgroundColor: '#f0fdf4'
            }}>
              <div style={{ fontSize: '0.75rem', color: '#22c55e', marginBottom: '0.5rem' }}>APPLICATION LAYER</div>
              <div style={{ fontWeight: 700, fontSize: '0.875rem', color: '#22c55e' }}>Your App</div>
            </div>
            <p style={{ fontSize: '0.8rem', color: '#666', marginTop: '1rem' }}>
              Sits within your app with full context awareness and simple integration
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
