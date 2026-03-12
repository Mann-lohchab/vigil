import { Request, Response, NextFunction } from 'express';

declare namespace vigil {
  interface RateLimitHeaders {
    remaining: string;
    reset: string;
    limit: string;
  }

  interface StorageOptions {
    type: 'memory' | 'redis';
    redis?: any;
    prefix?: string;
  }

  interface RateLimitOptions {
    /**
     * Mode of operation: 'LIVE' for actual rate limiting, 'TEST' to bypass
     * @default 'LIVE'
     */
    mode?: 'LIVE' | 'TEST';
    
    /**
     * Identifier for rate limiting. Can be:
     * - 'ip': Use IP address
     * - 'userId': Use user ID from request
     * - A custom function that returns a string key
     * @default 'ip'
     */
    by?: string | ((req: Request) => string);
    
    /**
     * Number of tokens to add per interval
     * @default 5
     */
    refillRate?: number;
    
    /**
     * Interval in seconds between token refills
     * @default 10
     */
    interval?: number;
    
    /**
     * Maximum token capacity
     * @default 10
     */
    capacity?: number;
    
    /**
     * Custom function to generate rate limit key
     */
    keyGenerator?: (req: Request) => string;
    
    /**
     * Whether to skip counting successful requests
     * @default false
     */
    skipSuccessfulRequests?: boolean;
    
    /**
     * Whether to skip counting failed requests
     * @default false
     */
    skipFailedRequests?: boolean;
    
    /**
     * Custom handler for when rate limit is exceeded
     */
    handler?: (req: Request, res: Response) => void;
    
    /**
     * Custom header names
     */
    headers?: RateLimitHeaders;
    
    /**
     * Disable starting token count at capacity
     * @default false
     */
    disableStart?: boolean;
    
    /**
     * Storage options
     */
    storage?: StorageOptions;
  }

  interface RateLimitInfo {
    tokens: number;
    lastRefill: number;
  }
}

declare function vigil(options?: vigil.RateLimitOptions): (req: Request, res: Response, next: NextFunction) => void;

declare namespace vigil {
  /**
   * Reset rate limit for a specific key or all keys
   */
  export function reset(key?: string): void;
  
  /**
   * Get current rate limit info for a key
   */
  export function getRateLimitInfo(key: string): RateLimitInfo | null;
  
  /**
   * Create a rate limiter with pre-configured options
   */
  export function create(options: RateLimitOptions): (req: Request, res: Response, next: NextFunction) => void;
}

export = vigil;
