
import { useEffect, useRef } from "react";
import { Link } from "react-router";
import gsap from "gsap";
import ColorBends from "./ColorBends";

export function GlitchHero() {
  const pathsRef = useRef<SVGPathElement[]>([]);

  useEffect(() => {
    const paths = pathsRef.current;

    paths.forEach((path) => {
      const length = path.getTotalLength();

      gsap.set(path, {
        strokeDasharray: length,
        strokeDashoffset: length,
      });
    });

    gsap.to(paths, {
      strokeDashoffset: 0,
      duration: 1.6,
      ease: "power3.out",
      stagger: 0.25,
    });
  }, []);

  return (
    <section
      className="section"
      style={{
        position: "relative",
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "120px 20px 80px",
        overflow: "hidden",
      }}
    >
      {/* Background */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          zIndex: 0,
        }}
      >
        <ColorBends
          colors={["#1a472a", "#2d5a3f", "#61dca3", "#4a9c6d"]}
          speed={0.3}
          rotation={45}
          scale={1.2}
          frequency={1.5}
          warpStrength={1.2}
          mouseInfluence={0.5}
          parallax={0.3}
          noise={0.05}
          transparent={true}
        />
      </div>

      {/* Content */}
      <div
        style={{
          position: "relative",
          zIndex: 1,
          textAlign: "center",
          maxWidth: "900px",
          width: "100%",
        }}
      >
        {/* Badge */}
        <div
          style={{
            display: "inline-block",
            backgroundColor: "rgba(206, 206, 206, 0.38)",
            color: "#858585",
            borderRadius: "9px",
            padding: "0.5rem 1rem",
            fontSize: "0.75rem",
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.15em",
            marginBottom: "1.5rem",
          }}
        >
          Security Middleware
        </div>

        {/* SVG Animated Logo */}
        <svg
          width="900"
          height="220"
          viewBox="0 0 900 220"
          fill="none"
          stroke="#5779ff"
          strokeWidth="10"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{
            maxWidth: "100%",
            marginBottom: "2rem",
            filter: "drop-shadow(0 0 20px rgba(87,121,255,0.5))",
          }}
        >
          {/* V */}
          <path
            ref={(el) => {
              if (el) pathsRef.current[0] = el;
            }}
            d="M80 40 L140 190 L200 40"
          />

          {/* I */}
          <path
            ref={(el) => {
              if (el) pathsRef.current[1] = el;
            }}
            d="M270 40 L270 190"
          />

          {/* G */}
          <path
            ref={(el) => {
              if (el) pathsRef.current[2] = el;
            }}
            d="
              M420 80
              A80 80 0 1 0 420 160
              L500 160
              L500 120
            "
          />

          {/* I */}
          <path
            ref={(el) => {
              if (el) pathsRef.current[3] = el;
            }}
            d="M600 40 L600 190"
          />

          {/* L */}
          <path
            ref={(el) => {
              if (el) pathsRef.current[4] = el;
            }}
            d="M700 40 L700 190 L790 190"
          />
        </svg>

        {/* Subheadline */}
        <p
          style={{
            marginBottom: "2.5rem",
            color: "rgba(0, 0, 0, 0.9)",
            maxWidth: "640px",
            margin: "0 auto 2.5rem",
            fontSize: "clamp(1rem, 2vw, 1.25rem)",
            lineHeight: 1.6,
            textShadow: "0 2px 10px rgba(0,0,0,0.8)",
          }}
        >
          Enterprise-grade security middleware for modern web applications.
          Block bots, prevent SQL injection, rate limit abuse, and verify
          emails all in one powerful package.
        </p>

        {/* Buttons */}
        <div
          style={{
            display: "flex",
            gap: "1rem",
            flexWrap: "wrap",
            justifyContent: "center",
          }}
        >
          <Link
            to="/docs"
            style={{
              backgroundColor: "#2563eb",
              color: "#0a0a0a",
              border: "3px solid #000000",
              boxShadow: "6px 6px 0px #000000",
              padding: "1rem 2rem",
              fontWeight: 700,
              fontSize: "1rem",
              cursor: "pointer",
              textDecoration: "none",
            }}
          >
            Get Started
          </Link>

          <Link
            to="/docs"
            style={{
              backgroundColor: "transparent",
              color: "#000000",
              border: "3px solid #000000",
              boxShadow: "6px 6px 0px #000000",
              padding: "1rem 2rem",
              fontWeight: 700,
              fontSize: "1rem",
              cursor: "pointer",
              textDecoration: "none",
            }}
          >
            View Docs
          </Link>
        </div>

        {/* Additional Info */}
        <div
          style={{
            marginTop: "3rem",
            display: "flex",
            justifyContent: "center",
            gap: "2rem",
            flexWrap: "wrap",
          }}
        >
          <div style={{ color: "rgba(0,0,0,0.7)", fontSize: "0.875rem" }}>
            <span style={{ color: "#2563eb", fontWeight: 700 }}>2</span> lines
            of code
          </div>

          <div style={{ color: "rgba(0,0,0,0.7)", fontSize: "0.875rem" }}>
            <span style={{ color: "#2563eb", fontWeight: 700 }}>6</span>{" "}
            security modules
          </div>

          <div style={{ color: "rgba(0,0,0,0.7)", fontSize: "0.875rem" }}>
            <span style={{ color: "#2563eb", fontWeight: 700 }}>
              {"<"}1ms
            </span>{" "}
            latency
          </div>
        </div>
      </div>

      {/* Bottom Gradient */}
      <div
        style={{
          position: "absolute",
          bottom: 0,
          left: 0,
          width: "100%",
          height: "150px",
          background:
            "linear-gradient(to top, rgba(0,0,0,0.8) 0%, transparent 100%)",
          pointerEvents: "none",
          zIndex: 1,
        }}
      />
    </section>
  );
}

