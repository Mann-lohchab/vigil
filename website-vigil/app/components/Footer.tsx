import { Link } from "react-router";

export function Footer() {
  const currentYear = new Date().getFullYear();
  
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-content">
          <div className="footer-section" style={{ maxWidth: '300px' }}>
            <h4 style={{ color: 'white', fontWeight: 800, fontSize: '1.5rem' }}>VIGIL</h4>
            <p style={{ color: '#a0a0a0', lineHeight: 1.6 }}>
              Security middleware for modern web applications. Protect your Express.js apps with enterprise-grade security.
            </p>
          </div>
          
          <div className="footer-section">
            <h4>Product</h4>
            <Link to="/docs">Documentation</Link>
            <Link to="/about">About</Link>
            <a href="https://github.com" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="#">Changelog</a>
          </div>
          
          <div className="footer-section">
            <h4>Resources</h4>
            <a href="#">API Reference</a>
            <a href="#">Examples</a>
            <a href="#">Blog</a>
            <a href="#">Community</a>
          </div>
          
          <div className="footer-section">
            <h4>Legal</h4>
            <a href="#">Privacy Policy</a>
            <a href="#">Terms of Service</a>
            <a href="#">License</a>
          </div>
        </div>
        
        <div className="footer-bottom">
          <p>© {currentYear} VIGIL Security. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
}
