import type { Route } from "./+types/home";
import { Navbar } from "../components/Navbar";
import { GlitchHero } from "../components/GlitchHero";
import { ProblemSection } from "../components/ProblemSection";
import { HowVigilWorks } from "../components/HowVigilWorks";
import { FeatureGrid } from "../components/FeatureGrid";
import { ArchitectureDiagram } from "../components/ArchitectureDiagram";
import { IntegrationSection } from "../components/IntegrationSection";
import { DeveloperExperience } from "../components/DeveloperExperience";
import { CTASection } from "../components/CTASection";
import { Footer } from "../components/Footer";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "VIGIL - Security Middleware for Modern Web Applications" },
    { name: "description", content: "Enterprise-grade security middleware for Express.js. Protect your applications with rate limiting, bot detection, SQL injection guard, and email verification." },
  ];
}

export default function Home() {
  return (
    <>
      <Navbar />
      <main>
        <GlitchHero />
        <ProblemSection />
        <HowVigilWorks />
        <FeatureGrid />
        <ArchitectureDiagram />
        <IntegrationSection />
        <DeveloperExperience />
        <CTASection />
      </main>
      <Footer />
    </>
  );
}
