import { Link, useLocation } from "react-router";

export function Navbar() {
  const location = useLocation();
  
  const isActive = (path: string) => location.pathname === path;
  
  return (
    <nav 
      className="navbar"
      style={{
        position: 'fixed',
        top: '12px',
        left: '50%',
        transform: 'translateX(-50%)',
        zIndex: 1000,
        backgroundColor: 'rgba(255, 255, 255, 0.15)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        boxShadow: '0 4px 30px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(255, 255, 255, 0.2)',
        borderRadius: '50px',
        padding: '12px 32px',
        width: 'auto',
        maxWidth: '600px',
        transition: 'all 0.3s ease',
      }}
    >
      <Link 
        to="/" 
        className="navbar-logo"
        style={{
          color: '#6b7280',
          textShadow: '0 0 10px rgba(107, 114, 128, 0.3)',
          marginRight: '48px',
        }}
      >
        VIGIL
      </Link>
      <div className="navbar-links">
        <Link 
          to="/" 
          className={`navbar-link ${isActive('/') ? 'navbar-link-active' : ''}`}
          style={{
            color: isActive('/') ? '#4b5563' : 'rgba(75, 85, 99, 0.9)',
            textShadow: isActive('/') ? '0 0 10px rgba(75, 85, 99, 0.3)' : 'none',
          }}
        >
          Home
        </Link>
        <Link 
          to="/docs" 
          className={`navbar-link ${isActive('/docs') ? 'navbar-link-active' : ''}`}
          style={{
            color: isActive('/docs') ? '#4b5563' : 'rgba(75, 85, 99, 0.9)',
            textShadow: isActive('/docs') ? '0 0 10px rgba(75, 85, 99, 0.3)' : 'none',
          }}
        >
          Docs
        </Link>
        <Link 
          to="/about" 
          className={`navbar-link ${isActive('/about') ? 'navbar-link-active' : ''}`}
          style={{
            color: isActive('/about') ? '#4b5563' : 'rgba(75, 85, 99, 0.9)',
            textShadow: isActive('/about') ? '0 0 10px rgba(75, 85, 99, 0.3)' : 'none',
          }}
        >
          About
        </Link>
        <a 
          href="https://github.com" 
          target="_blank" 
          rel="noopener noreferrer"
          className="navbar-link"
          style={{
            color: 'rgba(75, 85, 99, 0.9)',
          }}
        >
          GitHub
        </a>
      </div>
    </nav>
  );
}
