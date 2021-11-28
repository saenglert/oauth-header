import crypto from "crypto";

/**
 * Creates a random hex value
 * 
 * http://blog.tompawlak.org/how-to-generate-random-values-nodejs-javascript
 * 
 * @param len Length of the hex value
 * @returns  A random hex value of the desired length
 */
 export const randomValueHex =  (len: number): string => {
    return crypto.randomBytes(Math.ceil(len/2))
        .toString('hex') // convert to hexadecimal format
        .slice(0,len).toUpperCase();   // return required number of characters
}

/**
 * Returns current unix timestamp
 * @returns number
 */
export const unix = (): number => Math.floor(new Date().getTime() / 1000);

export enum SignatureMethods {
    PLAINTEXT = "PLAINTEXT",
    HMACSHA1 = "HMAC-SHA1",
    RSASHA1 = "RSA-SHA1",
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'PATCH' | 'TRACE' | 'OPTIONS' | 'CONNECT';

export class Generator {
    consumerKey: string;
    consumerSecret: string;
    tokenKey: string;
    tokenSecret: string;

    static seperator = ","

    /**
     * 
     * @param consumerKey 
     * @param consumerSecret 
     * @param tokenKey 
     * @param tokenSecret 
     */
    constructor(consumerKey: string, consumerSecret: string, tokenKey: string, tokenSecret: string) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.tokenKey = tokenKey;
        this.tokenSecret = tokenSecret;
    }


    /**
     * Generates the value for the Authorization header
     * 
     * @param httpMethod 
     * @param url If the url doesn't start with http or https https is added.
     * @param signatureMethod 
     * @returns 
     */
    public generateHeaderValue(httpMethod: HttpMethod, url: string, signatureMethod: SignatureMethods = SignatureMethods.HMACSHA1): string {
        let headerValue = "OAuth "
        const parameters = this.generateParameters(httpMethod, url, signatureMethod);

        parameters.forEach(value => {
            /**
             * Out of all paramteres only those relevant to OAuth may be added to he header value
             */
            if (Generator.isOAuthParameter(value[0])) {
                headerValue +="" + Generator.encode(value[0])+"=\""+ Generator.encode(value[1])+"\"" + Generator.seperator;
            }
        })

        // Remove trailing comma
        return headerValue.substring(0, headerValue.length - Generator.seperator.length);
    }

    /**
     * Generate the parameters for the Authorization header
     * 
     * @param method 
     * @param url 
     * @param signatureMethod 
     * @returns 
     */
    private generateParameters(method: HttpMethod, url: string, signatureMethod: string): any[] {
        const timestamp = unix().toString();
        const nonce = randomValueHex(16);
        const parameters: {[key: string]: string} = {
            "oauth_timestamp":        timestamp,
            "oauth_nonce":            nonce,
            "oauth_version":          "1.0",
            "oauth_signature_method": signatureMethod,
            "oauth_consumer_key":     this.consumerKey,
            "oauth_token": this.tokenKey
        };

        const parsedUrl = new URL(Generator.addHttpProtocolIfNotPresent(url));
        parsedUrl.searchParams.forEach((value, key) => {
            /** Can only key value pairs. No objects */
            parameters[key] = value;
        })

        const sorted = Generator.makeArrayOfParameters(parameters)
            .sort(Generator.requestParamSorter);
        
        const signature = Generator.generateSignature(
            method, 
            url, 
            Generator.normalizeRequestParameters(parameters), 
            this.consumerSecret, 
            this.tokenSecret,
            signatureMethod
        )

        sorted.push(["oauth_signature", signature])

        return sorted;
    }

    /**
     * Checks wether or not the url starts with the
     * @param url
     * @returns 
     */
    private static addHttpProtocolIfNotPresent(url: string) {
        if (!/^(?:f|ht)tps?\:\/\//.test(url)) {
            url = "https://" + url;
        }
        return url;        
    }

    /**
     * Generates the OAuth signature string given the methods parameters
     * and class members.
     * 
     * @param method 
     * @param url 
     * @param normalizedParameters 
     * @param consumerSecret 
     * @param tokenSecret 
     * @param signatureMethod 
     * @returns The OAuth signature to be used for the current request
     */
    private static generateSignature(method: HttpMethod, url: string, normalizedParameters: string, consumerSecret: string, tokenSecret: string, signatureMethod: string) {
        const signatureBase = Generator.generateSignatureBase(method, url, normalizedParameters);
        const key = `${Generator.encode(consumerSecret)}&${Generator.encode(tokenSecret)}`;

        let hash = "";
        switch (signatureMethod) {
            case SignatureMethods.PLAINTEXT:
                hash = key;
                break;
            case SignatureMethods.HMACSHA1:
                hash = crypto.createHmac("sha1", key).update(signatureBase).digest("base64");
                break;
            default:
                throw new Error(`Signature method ${signatureMethod} is not implemented`);
        }

        return hash;
        
    }

    /**
     * Generates the base string which is used in creating the OAuth signature
     * @see https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.1
     * @param method HTTP Method
     * @param url The URL the request is being made to
     * @param normalizedParameters 
     * @returns The signature base string
     */
    private static generateSignatureBase(method: HttpMethod, url: string, normalizedParameters: string): string {
        const encodedUrl = Generator.encode(Generator.normalizeUrl(url));
        const encodedParameters = Generator.encode(normalizedParameters);

        return `${method.toUpperCase()}&${encodedUrl}&${encodedParameters}`;
    }

    /**
     * Encode a string via percent encoding
     * 
     * @param toEncode
     * @returns The encoded string
     */
    private static encode(toEncode: string) {
        if( toEncode == null || toEncode == "" ) return ""
        else {
            var result= encodeURIComponent(toEncode);
            // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong
            return result.replace(/[!'()]/g, escape)
                .replace(/\*/g, "%2A");
        }
    }

    private static normalizeUrl(url: string) {
        var parsedUrl= new URL(url);
        var port ="";
        if( parsedUrl.port ) {
          if( (parsedUrl.protocol == "http:" && parsedUrl.port != "80" ) ||
              (parsedUrl.protocol == "https:" && parsedUrl.port != "443") ) {
                port= ":" + parsedUrl.port;
              }
        }
     
       if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
     
       return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
    }

    /**
     * Normalize request parameters into a single string
     * @see https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.1.3.2
     * @param parameters Object containing key-value-pairs
     * @returns A string containing all parameters for the request
     */
    private static normalizeRequestParameters(parameters: {[key: string]: string}): string {
        return Generator.makeArrayOfParameters(parameters)
        // First encode them #3.4.1.3.2 .1
        .map(value => {
            value[0]= Generator.encode( value[0] );
            value[1]= Generator.encode( value[1] );
            return value;
        })
        // Then sort them #3.4.1.3.2 .2
        .sort(Generator.requestParamSorter)
        // Then concatenate together #3.4.1.3.2 .3 & .4
        .reduce((prev,curr,index,arr) => {
            prev += curr[0];
            prev += "=";
            prev += curr[1];
            if (index < arr.length - 1) prev += "&";
            return prev;
        },"");
    }

    private static requestParamSorter(a: any[],b: any[]) {
        if ( a[0] == b[0] )  {
          return a[1] < b[1] ? -1 : 1;
        }
        else return a[0] < b[0] ? -1 : 1;
    }

    /**
     * Converts an object of key-value-pairs into an array
     * @param parameters 
     * @returns 
     */
    private static makeArrayOfParameters(parameters: {[key: string]: string}) {
        const pairs: any[] = [];
        Object.keys(parameters).forEach(key => {
            const value = parameters[key];
            if (Array.isArray(value)) {
                value.forEach(innerValue => {
                    pairs.push([key, innerValue])
                })
            } else {
                pairs.push([key, value]);
            }
        })
    
        return pairs;
    }

    /**
     * Checks wether a parameter is part of th OAuth process
     * @param parameter 
     * @returns True if paremeter contains oauth_ in its name
     */
    private static isOAuthParameter(parameter: string) {
        var m = parameter.match('^oauth_');
        return m && ( m[0] === "oauth_" );
    }
}