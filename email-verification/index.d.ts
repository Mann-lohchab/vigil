import { Request, Response, NextFunction } from 'express';

declare namespace vigil {
  namespace emailVerification {
    interface MXRecord {
      host: string;
      priority: number;
    }

    interface VerificationResult {
      email: string;
      valid: boolean;
      exists: boolean;
      hasMX: boolean;
      isDisposable: boolean;
      isValidFormat: boolean;
      isReserved: boolean;
      mxRecords: MXRecord[];
      errors: string[];
    }

    interface EmailVerificationOptions {
      /**
       * Mode of operation: 'LIVE' for actual verification, 'TEST' to bypass
       * @default 'LIVE'
       */
      mode?: 'LIVE' | 'TEST';
      
      /**
       * Check MX DNS records
       * @default true
       */
      checkMX?: boolean;
      
      /**
       * Check disposable email domains
       * @default true
       */
      checkDisposable?: boolean;
      
      /**
       * Custom list of disposable domains
       */
      disposableDomains?: string[];
      
      /**
       * DNS lookup timeout in milliseconds
       * @default 5000
       */
      timeout?: number;
      
      /**
       * Custom handler for invalid emails
       */
      handler?: (req: Request, res: Response, result: VerificationResult) => void;
      
      /**
       * Field name to check in request body/query
       * @default 'email'
       */
      emailField?: string;
      
      /**
       * Allow TEST mode to bypass verification
       * @default true
       */
      allowTestMode?: boolean;
    }
  }
}

declare function emailverification(options?: vigil.emailVerification.EmailVerificationOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;

declare namespace emailverification {
  /**
   * Verify an email address
   */
  export function verify(email: string, options?: EmailVerificationOptions): Promise<VerificationResult>;
  
  /**
   * Get list of disposable domains
   */
  export function getDisposableDomains(): string[];
  
  /**
   * Add custom disposable domain
   */
  export function addDisposableDomain(domain: string): void;
  
  /**
   * Create an email verifier with pre-configured options
   */
  export function create(options: EmailVerificationOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
}

export = emailverification;
