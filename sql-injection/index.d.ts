import { Request, Response, NextFunction } from 'express';

declare namespace vigil {
  namespace sqlInjection {
    interface Threat {
      type?: string;
      field?: string;
      value: string;
      detected: boolean;
      patterns: Array<{
        pattern: string;
        matched?: string;
        type?: string;
      }>;
    }

    interface SqlInjectionResult {
      detected: boolean;
      safe: boolean;
      threats: Threat[];
      errors: string[];
    }

    interface SqlInjectionOptions {
      /**
       * Text to check directly
       */
      text?: string;
      
      /**
       * Data object to scan
       */
      data?: object;
      
      /**
       * Check request body
       * @default true
       */
      checkBody?: boolean;
      
      /**
       * Check query parameters
       * @default true
       */
      checkQuery?: boolean;
      
      /**
       * Check route parameters
       * @default true
       */
      checkParams?: boolean;
      
      /**
       * Check headers
       * @default false
       */
      checkHeaders?: boolean;
      
      /**
       * Custom handler when injection detected
       */
      handler?: (req: Request, res: Response, threats: Threat[]) => void;
      
      /**
       * Throw error instead of JSON response
       * @default false
       */
      throwError?: boolean;
    }
  }
}

declare function sqlinjection(options?: vigil.sqlInjection.SqlInjectionOptions): Promise<vigil.sqlInjection.SqlInjectionResult>;

declare namespace sqlinjection {
  /**
   * Check text for SQL injection
   */
  export function detect(text: string): { detected: boolean; patterns: Array<{ pattern: string; matched?: string }> };
  
  /**
   * Create Express middleware
   */
  export function middleware(options?: vigil.sqlInjection.SqlInjectionOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
  
  /**
   * Alias for main function
   */
  export function check(options?: vigil.sqlInjection.SqlInjectionOptions): Promise<vigil.sqlInjection.SqlInjectionResult>;
}

export = sqlinjection;
