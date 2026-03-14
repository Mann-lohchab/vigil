import{w as s,p as e}from"./chunk-EPOLDU6W-DF41ubp-.js";import{N as a,F as l}from"./Footer-BKgmljf6.js";function p({}){return[{title:"Documentation - VIGIL Security"},{name:"description",content:"VIGIL documentation - Learn how to integrate security middleware into your Express.js applications."}]}const u=s(function(){const r=[{title:"Getting Started",description:"Learn how to install and set up VIGIL in your project.",links:[{text:"Installation",href:"#installation"},{text:"Quick Start",href:"#quick-start"},{text:"Configuration",href:"#configuration"}]},{title:"Security Modules",description:"Detailed documentation for each security module.",links:[{text:"Rate Limiting",href:"#rate-limiting"},{text:"Bot Detection",href:"#bot-detection"},{text:"SQL Injection Guard",href:"#sql-injection"},{text:"Email Verification",href:"#email-verification"},{text:"Request Monitoring",href:"#monitoring"},{text:"Policy Enforcement",href:"#policy"}]},{title:"API Reference",description:"Complete API documentation for VIGIL.",links:[{text:"vigil() Function",href:"#vigil-function"},{text:"Configuration Options",href:"#config-options"},{text:"Middleware Options",href:"#middleware"},{text:"Response Handling",href:"#responses"}]},{title:"Advanced",description:"Advanced usage patterns and customization.",links:[{text:"Custom Rules",href:"#custom-rules"},{text:"Logging",href:"#logging"},{text:"Testing",href:"#testing"},{text:"Performance",href:"#performance"}]}];return e.jsxs(e.Fragment,{children:[e.jsx(a,{}),e.jsxs("main",{style:{minHeight:"80vh",backgroundColor:"var(--color-background)"},children:[e.jsx("section",{style:{padding:"80px 20px",borderBottom:"3px solid var(--color-border)"},children:e.jsxs("div",{className:"container",children:[e.jsx("h1",{className:"text-heading-xl",style:{marginBottom:"1rem"},children:"Documentation"}),e.jsx("p",{className:"text-body-lg",style:{color:"#666",maxWidth:"600px"},children:"Everything you need to integrate VIGIL security middleware into your Express.js applications."})]})}),e.jsx("section",{style:{padding:"60px 20px"},children:e.jsxs("div",{className:"container",children:[e.jsx("div",{style:{display:"grid",gridTemplateColumns:"repeat(2, 1fr)",gap:"2rem"},children:r.map((t,n)=>e.jsxs("div",{className:"brutalist-card",children:[e.jsx("h2",{style:{fontSize:"1.25rem",fontWeight:700,marginBottom:"0.75rem"},children:t.title}),e.jsx("p",{style:{color:"#666",marginBottom:"1rem",fontSize:"0.875rem"},children:t.description}),e.jsx("ul",{style:{listStyle:"none",padding:0,margin:0},children:t.links.map((i,o)=>e.jsx("li",{style:{marginBottom:"0.5rem"},children:e.jsxs("a",{href:i.href,style:{color:"var(--color-primary-blue)",textDecoration:"none",fontWeight:600,fontSize:"0.875rem"},children:["→ ",i.text]})},o))})]},n))}),e.jsxs("div",{style:{marginTop:"4rem"},children:[e.jsx("h2",{style:{fontSize:"1.5rem",fontWeight:700,marginBottom:"1rem"},children:"Quick Example"}),e.jsx("div",{className:"code-block",children:`import express from 'express';
import { vigil } from 'vigil-security';

const app = express();

// Add VIGIL middleware with custom configuration
app.use(vigil({
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per window
  },
  botDetection: {
    enabled: true,
    strictMode: true
  },
  sqlGuard: {
    enabled: true,
    logAttacks: true
  }
}));

// Your routes
app.get('/api/data', (req, res) => {
  res.json({ data: 'Secure response' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});`})]})]})})]}),e.jsx(l,{})]})});export{u as default,p as meta};
