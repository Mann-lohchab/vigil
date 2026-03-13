/**
 * Example: Using Vigil Rate Limiting, Bot Detection, and Email Verification
 *
 * This example demonstrates how to use vigil's modules in an Express.js application.
 */

const express = require("express");
const { ratelimiting, botDetection, emailVerification } = require("./index");

const app = express();

// Parse JSON bodies
app.use(express.json());

//Bot Detection Middleware
// app.use(botDetection({
  // mode: 'LIVE',
   //searchEngine: ['google', 'bing', 'yahoo', 'yandex', 'baidu']
 //}));

// Rate Limiting Middleware
app.use(
  ratelimiting({
    mode: "LIVE",
    by: "userId",
    refillRate: 5,
    interval: 10,
    capacity: 10,
  }),
);

// Email Verification Middleware
app.use(
  emailVerification.middleware({
    source: "body",
    checkMX: true,
    checkDisposable: true,
    blockOnDisposable: true,
  }),
);

// Routes
app.get("/", (req, res) => {
  res.json({
    message: "Welcome to the API!",
    userId: req.headers["x-user-id"] || "anonymous",
  });
});

app.get("/api/data", (req, res) => {
  res.json({
    data: "Sample data",
    timestamp: new Date().toISOString(),
    isBot: req.isBot,
    searchEngine: req.searchEngine,
  });
});

// Email verification endpoint
app.post("/api/verify-email", (req, res) => {
  const email = req.body.email;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  // Email verification is done by middleware, result is in req.emailVerification
  res.json({
    email,
    verification: req.emailVerification,
  });
});

// Direct email verification API
app.post("/api/email/check", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const result = await emailVerification.verify(email);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Example: Rate limit info endpoint
app.get("/api/rate-limit/:key", (req, res) => {
  const info = ratelimiting.getRateLimitInfo(req.params.key);
  if (info) {
    res.json(info);
  } else {
    res.json({ message: "No rate limit data found for this key" });
  }
});

// Example: Reset rate limit
app.post("/api/rate-limit/reset", (req, res) => {
  const { key } = req.body;
  if (key) {
    ratelimiting.reset(key);
    res.json({ message: `Rate limit reset for key: ${key}` });
  } else {
    ratelimiting.reset();
    res.json({ message: "All rate limits reset" });
  }
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`\n=== Vigil Middleware Enabled ===`);
  console.log(`Rate limiting: 5 tokens/10sec, capacity 10`);
  console.log(`Bot detection: google, bing, yahoo, yandex, baidu`);
  console.log(`Email verification: MX record check enabled`);
  console.log(`\n=== Test Commands ===`);
  console.log(`Verify email:`);
  console.log(
    `  curl -X POST -H "Content-Type: application/json" -d '{"email":"test@gmail.com"}' http://localhost:${PORT}/api/email/check`,
  );
  console.log(`\nCheck disposable email:`);
  console.log(
    `  curl -X POST -H "Content-Type: application/json" -d '{"email":"test@mailinator.com"}' http://localhost:${PORT}/api/email/check`,
  );
});
