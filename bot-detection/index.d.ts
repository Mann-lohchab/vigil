import { Request, Response, NextFunction } from 'express';

declare namespace vigil {
  namespace botDetection {
    interface BotInfo {
      isBot: boolean;
      botName: string | null;
      searchEngine: string | null;
      url?: string;
      ua?: string;
    }

    interface BotDetectionOptions {
      /**
       * Mode of operation: 'LIVE' for actual detection, 'TEST' to bypass
       * @default 'LIVE'
       */
      mode?: 'LIVE' | 'TEST';
      
      /**
       * List of allowed search engine bots
       * Available: google, googleother, googleother2, bing, msnbot, yahoo, yandex, baidu, duckduckgo, facebook, twitter, apple, semrush, ahrefs, moz, slack, telegram, discord, wget, curl, python, node, playwright, puppeteer
       * @default All search engines
       */
      searchEngine?: string[];
      
      /**
       * List of User-Agents to always allow
       */
      allowList?: (string | RegExp)[];
      
      /**
       * List of User-Agents to always block
       */
      blockList?: (string | RegExp)[];
      
      /**
       * Custom handler for detected bots
       */
      handler?: (req: Request, res: Response, botInfo: BotInfo) => void;
      
      /**
       * Set X-Bot-Detected header
       * @default true
       */
      setHeader?: boolean;
      
      /**
       * Property name to attach bot info to request
       * @default 'isBot'
       */
      botProperty?: string;
      
      /**
       * Property name to attach search engine info to request
       * @default 'searchEngine'
       */
      searchEngineProperty?: string;
      
      /**
       * Allow authenticated users (skip bot detection)
       * @default true
       */
      allowAuthenticated?: boolean;
    }
  }
}

declare function botdetection(options?: vigil.botDetection.BotDetectionOptions): (req: Request, res: Response, next: NextFunction) => void;

declare namespace botdetection {
  /**
   * Detect if a User-Agent belongs to a bot
   */
  export function detect(userAgent: string): BotInfo;
  
  /**
   * Get all available search engine keys
   */
  export function getSearchEngines(): string[];
  
  /**
   * Create a bot detector with pre-configured options
   */
  export function create(options: BotDetectionOptions): (req: Request, res: Response, next: NextFunction) => void;
}

export = botdetection;
