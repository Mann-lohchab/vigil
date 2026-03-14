import { Link } from "react-router";

export function CTASection() {
  return (
    <section className="section" style={{ backgroundColor: 'var(--color-primary-blue)', paddingBottom: '100px' }}>
      <div className="container" style={{ textAlign: 'center' }}>
        <h2 className="text-heading-lg" style={{ marginBottom: '1rem', color: 'white' }}>
          Ready to Secure Your Application?
        </h2>
        <p style={{ color: 'rgba(255,255,255,0.9)', fontSize: '1.125rem', marginBottom: '2rem', maxWidth: '500px', margin: '0 auto 2rem' }}>
          Add VIGIL to your Express.js app in under 2 minutes. 
          Start with zero configuration.
        </p>
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link 
            to="/docs" 
            className="btn-secondary"
            style={{ backgroundColor: 'white', borderColor: 'white' }}
          >
            Read Documentation
          </Link>
          <a 
            href="https://github.com" 
            target="_blank" 
            rel="noopener noreferrer"
            className="btn-secondary"
            style={{ backgroundColor: 'var(--color-primary-blue)', color: 'white', borderColor: 'white' }}
          >
            View on GitHub
          </a>
        </div>
      </div>
    </section>
  );
}
