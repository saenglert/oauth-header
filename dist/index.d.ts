/**
 * Creates a random hex value
 *
 * http://blog.tompawlak.org/how-to-generate-random-values-nodejs-javascript
 *
 * @param len Length of the hex value
 * @returns  A random hex value of the desired length
 */
export declare const randomValueHex: (len: number) => string;
/**
 * Returns current unix timestamp
 * @returns number
 */
export declare const unix: () => number;
export declare enum SignatureMethods {
    PLAINTEXT = "PLAINTEXT",
    HMACSHA1 = "HMAC-SHA1",
    RSASHA1 = "RSA-SHA1"
}
export declare type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'PATCH' | 'TRACE' | 'OPTIONS' | 'CONNECT';
export declare class OAuthHeader {
    consumerKey: string;
    consumerSecret: string;
    tokenKey: string;
    tokenSecret: string;
    static seperator: string;
    /**
     *
     * @param consumerKey
     * @param consumerSecret
     * @param tokenKey
     * @param tokenSecret
     */
    constructor(consumerKey: string, consumerSecret: string, tokenKey: string, tokenSecret: string);
    /**
     * Generates the value for the Authorization header.
     */
    generateHeaderValue(httpMethod: HttpMethod, url: string, signatureMethod?: SignatureMethods): string;
    /**
     * Generate the parameters for the Authorization header
     *
     * @param method
     * @param url
     * @param signatureMethod
     * @returns
     */
    private generateParameters;
    private static generateSignature;
    /**
     * Generates the base string which is used in creating the OAuth signature
     * @see https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.1
     * @param method HTTP Method
     * @param url The URL the request is being made to
     * @param normalizedParameters
     * @returns
     */
    private static generateSignatureBase;
    /**
     * Encode a string via percent encoding
     *
     * @param toEncode
     * @returns The encoded string
     */
    private static encode;
    private static normalizeUrl;
    /**
     * Normalize request parameters into a single string
     * @see https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.1.3.2
     * @param parameters Object containing key-value-pairs
     * @returns A string containing all parameters for the request
     */
    private static normalizeRequestParameters;
    private static requestParamSorter;
    /**
     * Converts an object of key-value-pairs into an array
     * @param parameters
     * @returns
     */
    private static makeArrayOfParameters;
    /**
     * Checks wether a parameter is part of th OAuth process
     * @param parameter
     * @returns True if paremeter contains oauth_ in its name
     */
    private static isOAuthParameter;
}
//# sourceMappingURL=index.d.ts.map