import type { Route } from "./+types/about";
import { Navbar } from "../components/Navbar";
import { Footer } from "../components/Footer";
import { GitHubIcon, DiscordIcon, TwitterIcon } from "../components/Icons";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "About - VIGIL Security" },
    { name: "description", content: "Learn about VIGIL Security - the security middleware for modern web applications." },
  ];
}

export default function About() {
  return (
    <>
      <Navbar />
      <main style={{ minHeight: '80vh', backgroundColor: 'var(--color-background)', paddingTop: '80px' }}>
        <section style={{ padding: '80px 20px', borderBottom: '3px solid var(--color-border)' }}>
          <div className="container">
            <h1 className="text-heading-xl" style={{ marginBottom: '1rem' }}>
              About VIGIL
            </h1>
            <p className="text-body-lg" style={{ color: '#666', maxWidth: '700px' }}>
              VIGIL is an open-source security middleware designed to protect modern web applications 
              from common security threats with minimal configuration.
            </p>
          </div>
        </section>
        
        <section style={{ padding: '60px 20px' }}>
          <div className="container">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '3rem' }}>
              {/* Mission */}
              <div>
                <h2 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '1rem' }}>
                  Our Mission
                </h2>
                <p style={{ color: '#666', lineHeight: 1.8, marginBottom: '1.5rem' }}>
                  We believe security should be accessible to every developer. Too often, 
                  security is treated as an afterthought or requires expensive enterprise solutions. 
                  VIGIL aims to change that by providing enterprise-grade security as a simple, 
                  free-to-use middleware.
                </p>
                <p style={{ color: '#666', lineHeight: 1.8 }}>
                  Born from the challenges of AI-assisted development, VIGIL addresses the 
                  security gap created by rapid prototyping and fast iteration cycles. 
                  We're here to ensure speed doesn't come at the cost of security.
                </p>
              </div>
              
              {/* Values */}
              <div>
                <h2 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '1rem' }}>
                  Our Values
                </h2>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div className="brutalist-card-blue" style={{ padding: '1rem' }}>
                    <h3 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Developer First</h3>
                    <p style={{ color: '#666', fontSize: '0.875rem' }}>
                      Every decision we make starts with the developer experience. 
                      Simple APIs, clear documentation, and intuitive design.
                    </p>
                  </div>
                  
                  <div className="brutalist-card-blue" style={{ padding: '1rem' }}>
                    <h3 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Open Source</h3>
                    <p style={{ color: '#666', fontSize: '0.875rem' }}>
                      Security should be transparent and auditable. 
                      VIGIL is open source with permissive licensing.
                    </p>
                  </div>
                  
                  <div className="brutalist-card-blue" style={{ padding: '1rem' }}>
                    <h3 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Continuous Improvement</h3>
                    <p style={{ color: '#666', fontSize: '0.875rem' }}>
                      Security threats evolve daily. We're committed to staying ahead 
                      and providing regular updates.
                    </p>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Team / Contact */}
            <div style={{ marginTop: '4rem', paddingTop: '3rem', borderTop: '3px solid var(--color-border)' }}>
              <h2 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '1.5rem' }}>
                Get Involved
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '2rem' }}>
                <div className="brutalist-card" style={{ textAlign: 'center' }}>
                  <div style={{ color: 'var(--color-primary-blue)', marginBottom: '1rem' }}>
                    <GitHubIcon size={32} />
                  </div>
                  <h3 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>GitHub</h3>
                  <p style={{ color: '#666', fontSize: '0.875rem' }}>
                    Star us, report issues, and contribute to the codebase.
                  </p>
                  <a href="https://github.com" style={{ 
                    color: 'var(--color-primary-blue)', 
                    fontWeight: 600,
                    fontSize: '0.875rem'
                  }}>
                    github.com/vigil-security →
                  </a>
                </div>
                
                <div className="brutalist-card" style={{ textAlign: 'center' }}>
                  <div style={{ color: '#5865F2', marginBottom: '1rem' }}>
                    <DiscordIcon size={32} />
                  </div>
                  <h3 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Discord</h3>
                  <p style={{ color: '#666', fontSize: '0.875rem' }}>
                    Join our community to ask questions and share ideas.
                  </p>
                  <a href="#" style={{ 
                    color: 'var(--color-primary-blue)', 
                    fontWeight: 600,
                    fontSize: '0.875rem'
                  }}>
                    Join Discord →
                  </a>
                </div>
                
                <div className="brutalist-card" style={{ textAlign: 'center' }}>
                  <div style={{ marginBottom: '1rem' }}>
                    <TwitterIcon size={32} />
                  </div>
                  <h3 style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Twitter</h3>
                  <p style={{ color: '#666', fontSize: '0.875rem' }}>
                    Follow us for updates, security tips, and news.
                  </p>
                  <a href="#" style={{ 
                    color: 'var(--color-primary-blue)', 
                    fontWeight: 600,
                    fontSize: '0.875rem'
                  }}>
                    Follow @vigil →
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
