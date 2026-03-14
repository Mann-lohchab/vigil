import { RocketIcon, PuzzleIcon, LightningIcon, WindIcon, BoxIcon, WrenchIcon } from "./Icons";

export function DeveloperExperience() {
  const features = [
    {
      icon: <RocketIcon size={32} />,
      title: "Zero Configuration",
      description: "Get started in seconds. VIGIL works out of the box with sensible defaults for all security modules."
    },
    {
      icon: <PuzzleIcon size={32} />,
      title: "Modular Architecture",
      description: "Enable or disable specific modules. Import only what you need. Full control over your security stack."
    },
    {
      icon: <LightningIcon size={32} />,
      title: "Fast Integration",
      description: "Two lines of code to protect your entire application. No complex setup or external services required."
    },
    {
      icon: <WindIcon size={32} />,
      title: "Lightweight Runtime",
      description: "Minimal performance overhead. Sub-millisecond latency for most security checks."
    },
    {
      icon: <BoxIcon size={32} />,
      title: "Express.js Compatible",
      description: "Built specifically for Express.js. Works seamlessly with your existing middleware and routes."
    },
    {
      icon: <WrenchIcon size={32} />,
      title: "Developer Friendly",
      description: "Clear error messages, comprehensive logging, and intuitive APIs make debugging easy."
    }
  ];

  return (
    <section className="section" style={{ backgroundColor: 'var(--color-light-background)' }}>
      <div className="container">
        <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
          <h2 className="text-heading-lg" style={{ marginBottom: '1rem' }}>
            Developer Experience
          </h2>
          <p className="text-body-lg" style={{ color: '#666', maxWidth: '600px', margin: '0 auto' }}>
            Built by developers, for developers. Security that doesn't get in your way.
          </p>
        </div>
        
        <div className="grid-3">
          {features.map((feature, index) => (
            <div key={index} className="brutalist-card" style={{ height: '100%' }}>
              <div style={{ 
                marginBottom: '1rem',
                color: 'var(--color-primary-blue)'
              }}>
                {feature.icon}
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, marginBottom: '0.75rem' }}>
                {feature.title}
              </h3>
              <p style={{ color: '#666', lineHeight: 1.6, fontSize: '0.875rem' }}>
                {feature.description}
              </p>
            </div>
          ))}
        </div>
        
        {/* Stats */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(4, 1fr)', 
          gap: '2rem', 
          marginTop: '4rem',
          padding: '2rem',
          backgroundColor: 'var(--color-primary-blue)',
          border: '3px solid var(--color-border)',
          boxShadow: 'var(--brutalist-shadow)'
        }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 800, color: 'white' }}>2</div>
            <div style={{ fontSize: '0.875rem', color: 'rgba(255,255,255,0.8)' }}>Lines of Code</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 800, color: 'white' }}>6</div>
            <div style={{ fontSize: '0.875rem', color: 'rgba(255,255,255,0.8)' }}>Security Modules</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 800, color: 'white' }}>{"<"}1ms</div>
            <div style={{ fontSize: '0.875rem', color: 'rgba(255,255,255,0.8)' }}>Latency</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '2.5rem', fontWeight: 800, color: 'white' }}>100%</div>
            <div style={{ fontSize: '0.875rem', color: 'rgba(255,255,255,0.8)' }}>TypeScript</div>
          </div>
        </div>
      </div>
    </section>
  );
}
