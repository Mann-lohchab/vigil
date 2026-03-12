/**
 * Vigil - Bot Detection Middleware for Express.js
 * 
 * Detects search engine bots and other crawlers based on User-Agent
 */

// Known search engine bots
const SEARCH_ENGINES = {
  google: {
    name: 'Googlebot',
    pattern: /googlebot\/[0-9.]+/i,
    url: 'https://www.google.com/bot.html'
  },
  googleother: {
    name: 'GoogleOther',
    pattern: /googleother\/[0-9.]+/i,
    url: 'https://www.google.com/bot.html'
  },
  googleother2: {
    name: 'GoogleOther-Image',
    pattern: /googleother-image\/[0-9.]+/i,
    url: 'https://www.google.com/bot.html'
  },
  bing: {
    name: 'Bingbot',
    pattern: /bingbot\/[0-9.]+/i,
    url: 'https://www.bing.com/bot.htm'
  },
  msnbot: {
    name: 'MSNBot',
    pattern: /msnbot\/[0-9.]+/i,
    url: 'https://www.bing.com/bot.htm'
  },
  yahoo: {
    name: 'Yahoo! Slurp',
    pattern: /slurp/i,
    url: 'https://help.yahoo.com/help/us/ysearch/slurp'
  },
  yandex: {
    name: 'YandexBot',
    pattern: /yandexbot\/[0-9.]+/i,
    url: 'https://yandex.com/bots'
  },
  baidu: {
    name: 'Baiduspider',
    pattern: /baiduspider/i,
    url: 'https://www.baidu.com/search/spider.html'
  },
  duckduckgo: {
    name: 'DuckDuckBot',
    pattern: /duckduckbot\/[0-9.]+/i,
    url: 'https://duckduckgo.com/bot/'
  },
  facebook: {
    name: 'FacebookBot',
    pattern: /facebookexternalhit\/[0-9.]+/i,
    url: 'https://developers.facebook.com/docs/sharing/webmasters/crawler'
  },
  twitter: {
    name: 'TwitterBot',
    pattern: /twitterbot\/[0-9.]+/i,
    url: 'https://developer.twitter.com/en/docs/twitter-api/v1'
  },
  apple: {
    name: 'Applebot',
    pattern: /applebot\/[0-9.]+/i,
    url: 'https://support.apple.com/en-us/HT204683'
  },
  semrush: {
    name: 'SemrushBot',
    pattern: /semrushbot\/[0-9.]+/i,
    url: 'https://www.semrush.com/bot/'
  },
  ahrefs: {
    name: 'AhrefsBot',
    pattern: /ahrefsbot\/[0-9.]+/i,
    url: 'https://ahrefs.com/robot/'
  },
  moz: {
    name: 'Mozscape',
    pattern: /rogerbot\/[0-9.]+/i,
    url: 'https://moz.com/researchbots'
  },
  slack: {
    name: 'Slackbot',
    pattern: /slackbot\/[0-9.]+/i,
    url: 'https://api.slack.com/robots'
  },
  telegram: {
    name: 'TelegramBot',
    pattern: /telegrambot/i,
    url: 'https://core.telegram.org/bots/api'
  },
  discord: {
    name: 'Discordbot',
    pattern: /discordbot\/[0-9.]+/i,
    url: 'https://discord.com/developers/docs/topics/gateway'
  },
  wget: {
    name: 'Wget',
    pattern: /^Wget\//i,
    url: 'https://www.gnu.org/software/wget/'
  },
  curl: {
    name: 'curl',
    pattern: /^curl\//i,
    url: 'https://curl.haxx.se/'
  },
  python: {
    name: 'Python-urllib',
    pattern: /python-urllib\/[0-9.]+/i,
    url: 'https://docs.python.org/3/library/urllib.request.html'
  },
  node: {
    name: 'Node.js',
    pattern: /^node\//i,
    url: 'https://nodejs.org/'
  },
  playwright: {
    name: 'Playwright',
    pattern: /playwright\/[0-9.]+/i,
    url: 'https://playwright.dev/'
  },
  puppeteer: {
    name: 'Puppeteer',
    pattern: /puppeteer\/[0-9.]+/i,
    url: 'https://pptr.dev/'
  }
};

// Known bot indicators in User-Agent
const BOT_INDICATORS = [
  /bot/i,
  /crawler/i,
  /spider/i,
  /scraper/i,
  /curl/i,
  /wget/i,
  /python/i,
  /java\//i,
  /go-http/i,
  /httpclient/i,
  /fetch/i,
  /headless/i,
  /automation/i,
  /phantom/i,
  /selenium/i,
  /puppeteer/i,
  /playwright/i,
  /apify/i,
  /scrapy/i
];

const DEFAULT_OPTIONS = {
  mode: 'LIVE',
  searchEngine: Object.keys(SEARCH_ENGINES),
  allowList: [],
  blockList: [],
  handler: null,
  setHeader: true,
  botProperty: 'isBot',
  searchEngineProperty: 'searchEngine',
  allowAuthenticated: true
};

/**
 * Detect if a User-Agent belongs to a bot
 */
function detectBot(userAgent) {
  if (!userAgent) {
    return { isBot: false, botName: null, searchEngine: null };
  }

  // Check against known search engines first
  for (const [key, engine] of Object.entries(SEARCH_ENGINES)) {
    if (engine.pattern.test(userAgent)) {
      return {
        isBot: true,
        botName: engine.name,
        searchEngine: key,
        url: engine.url
      };
    }
  }

  // Check against general bot indicators
  for (const indicator of BOT_INDICATORS) {
    if (indicator.test(userAgent)) {
      return {
        isBot: true,
        botName: 'Unknown Bot',
        searchEngine: null,
        ua: userAgent
      };
    }
  }

  return { isBot: false, botName: null, searchEngine: null };
}

/**
 * Check if a specific search engine is allowed
 */
function isSearchEngineAllowed(searchEngine, allowedEngines) {
  if (!searchEngine || allowedEngines.length === 0) {
    return true;
  }
  return allowedEngines.includes(searchEngine);
}

/**
 * Create bot detection middleware
 * 
 * @param {Object} options - Bot detection options
 * @param {string} [options.mode='LIVE'] - Mode: 'LIVE' or 'TEST'
 * @param {string[]} [options.searchEngine=['google','bing','yandex','baidu',...]] - Allowed search engines
 * @param {string[]} [options.allowList=[]] - List of User-Agents to always allow
 * @param {string[]} [options.blockList=[]] - List of User-Agents to always block
 * @param {Function} [options.handler] - Custom handler for detected bots
 * @param {boolean} [options.setHeader=true] - Set X-Bot-Detected header
 * @param {string} [options.botProperty='isBot'] - Property name to attach bot info to request
 * @param {boolean} [options.allowAuthenticated=true] - Allow authenticated users
 * @returns {Function} Express middleware
 */
function botdetection(options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  
  // Validate mode
  if (!['LIVE', 'TEST'].includes(opts.mode)) {
    throw new Error('mode must be either "LIVE" or "TEST"');
  }

  return (req, res, next) => {
    // In TEST mode, skip bot detection
    if (opts.mode === 'TEST') {
      return next();
    }

    // Allow authenticated users by default
    if (opts.allowAuthenticated && (req.user || req.isAuthenticated?.())) {
      return next();
    }

    const userAgent = req.headers['user-agent'] || '';
    const botInfo = detectBot(userAgent);
    
    // Check allow list
    if (opts.allowList.length > 0) {
      for (const allowed of opts.allowList) {
        if (typeof allowed === 'string' && userAgent.includes(allowed)) {
          return next();
        }
        if (allowed instanceof RegExp && allowed.test(userAgent)) {
          return next();
        }
      }
    }

    // Check block list
    if (opts.blockList.length > 0) {
      for (const blocked of opts.blockList) {
        if (typeof blocked === 'string' && userAgent.includes(blocked)) {
          // Block this bot
          if (opts.handler) {
            return opts.handler(req, res, botInfo);
          }
          
          return res.status(403).json({
            error: 'Forbidden',
            message: 'Access denied. Your User-Agent has been blocked.'
          });
        }
        if (blocked instanceof RegExp && blocked.test(userAgent)) {
          // Block this bot
          if (opts.handler) {
            return opts.handler(req, res, botInfo);
          }
          
          return res.status(403).json({
            error: 'Forbidden',
            message: 'Access denied. Your User-Agent has been blocked.'
          });
        }
      }
    }

    // If it's a bot but not in allowed search engines, handle it
    if (botInfo.isBot) {
      if (!isSearchEngineAllowed(botInfo.searchEngine, opts.searchEngine)) {
        if (opts.handler) {
          return opts.handler(req, res, botInfo);
        }
        
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Search engine bots are not allowed.'
        });
      }

      // Set header indicating bot detected
      if (opts.setHeader) {
        res.set('X-Bot-Detected', 'true');
        if (botInfo.searchEngine) {
          res.set('X-Search-Engine', botInfo.searchEngine);
        }
      }
    }

    // Attach bot info to request
    if (opts.botProperty) {
      req[opts.botProperty] = botInfo.isBot;
    }
    if (opts.searchEngineProperty && botInfo.searchEngine) {
      req[opts.searchEngineProperty] = botInfo.searchEngine;
    }

    next();
  };
}

/**
 * Get bot info for a User-Agent (utility function)
 */
botdetection.detect = function(userAgent) {
  return detectBot(userAgent);
};

/**
 * Get all available search engines
 */
botdetection.getSearchEngines = function() {
  return Object.keys(SEARCH_ENGINES);
};

/**
 * Create a bot detector with pre-configured options
 */
botdetection.create = function(options) {
  return botdetection(options);
};

module.exports = botdetection;
