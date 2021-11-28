"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuthHeader = exports.SignatureMethods = exports.unix = exports.randomValueHex = void 0;
const crypto_1 = __importDefault(require("crypto"));
/**
 * Creates a random hex value
 *
 * http://blog.tompawlak.org/how-to-generate-random-values-nodejs-javascript
 *
 * @param len Length of the hex value
 * @returns  A random hex value of the desired length
 */
const randomValueHex = (len) => {
    return crypto_1.default.randomBytes(Math.ceil(len / 2))
        .toString('hex') // convert to hexadecimal format
        .slice(0, len).toUpperCase(); // return required number of characters
};
exports.randomValueHex = randomValueHex;
/**
 * Returns current unix timestamp
 * @returns number
 */
const unix = () => Math.floor(new Date().getTime() / 1000);
exports.unix = unix;
var SignatureMethods;
(function (SignatureMethods) {
    SignatureMethods["PLAINTEXT"] = "PLAINTEXT";
    SignatureMethods["HMACSHA1"] = "HMAC-SHA1";
    SignatureMethods["RSASHA1"] = "RSA-SHA1";
})(SignatureMethods = exports.SignatureMethods || (exports.SignatureMethods = {}));
class OAuthHeader {
    /**
     *
     * @param consumerKey
     * @param consumerSecret
     * @param tokenKey
     * @param tokenSecret
     */
    constructor(consumerKey, consumerSecret, tokenKey, tokenSecret) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.tokenKey = tokenKey;
        this.tokenSecret = tokenSecret;
    }
    /**
     * Generates the value for the Authorization header.
     */
    generateHeaderValue(httpMethod, url, signatureMethod = SignatureMethods.HMACSHA1) {
        let headerValue = "OAuth ";
        const parameters = this.generateParameters(httpMethod, url, signatureMethod);
        parameters.forEach(value => {
            /**
             * Out of all paramteres only those relevant to OAuth may be added to he header value
             */
            if (OAuthHeader.isOAuthParameter(value[0])) {
                headerValue += "" + OAuthHeader.encode(value[0]) + "=\"" + OAuthHeader.encode(value[1]) + "\"" + OAuthHeader.seperator;
            }
        });
        // Remove trailing comma
        return headerValue.substring(0, headerValue.length - OAuthHeader.seperator.length);
    }
    /**
     * Generate the parameters for the Authorization header
     *
     * @param method
     * @param url
     * @param signatureMethod
     * @returns
     */
    generateParameters(method, url, signatureMethod) {
        const timestamp = (0, exports.unix)().toString();
        const nonce = (0, exports.randomValueHex)(16);
        const parameters = {
            "oauth_timestamp": timestamp,
            "oauth_nonce": nonce,
            "oauth_version": "1.0",
            "oauth_signature_method": signatureMethod,
            "oauth_consumer_key": this.consumerKey,
            "oauth_token": this.tokenKey
        };
        const parsedUrl = new URL(url);
        parsedUrl.searchParams.forEach((value, key) => {
            /** Can only key value pairs. No objects */
            parameters[key] = value;
        });
        const sorted = OAuthHeader.makeArrayOfParameters(parameters)
            .sort(OAuthHeader.requestParamSorter);
        const signature = OAuthHeader.generateSignature(method, url, OAuthHeader.normalizeRequestParameters(parameters), this.consumerSecret, this.tokenSecret, signatureMethod);
        sorted.push(["oauth_signature", signature]);
        return sorted;
    }
    static generateSignature(method, url, normalizedParameters, consumerSecret, tokenSecret, signatureMethod) {
        const signatureBase = OAuthHeader.generateSignatureBase(method, url, normalizedParameters);
        const key = `${OAuthHeader.encode(consumerSecret)}&${OAuthHeader.encode(tokenSecret)}`;
        let hash = "";
        switch (signatureMethod) {
            case SignatureMethods.PLAINTEXT:
                hash = key;
                break;
            case SignatureMethods.HMACSHA1:
                hash = crypto_1.default.createHmac("sha1", key).update(signatureBase).digest("base64");
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
     * @returns
     */
    static generateSignatureBase(method, url, normalizedParameters) {
        const encodedUrl = OAuthHeader.encode(OAuthHeader.normalizeUrl(url));
        const encodedParameters = OAuthHeader.encode(normalizedParameters);
        return `${method.toUpperCase()}&${encodedUrl}&${encodedParameters}`;
    }
    /**
     * Encode a string via percent encoding
     *
     * @param toEncode
     * @returns The encoded string
     */
    static encode(toEncode) {
        if (toEncode == null || toEncode == "")
            return "";
        else {
            var result = encodeURIComponent(toEncode);
            // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong
            return result.replace(/[!'()]/g, escape)
                .replace(/\*/g, "%2A");
        }
    }
    static normalizeUrl(url) {
        var parsedUrl = new URL(url);
        var port = "";
        if (parsedUrl.port) {
            if ((parsedUrl.protocol == "http:" && parsedUrl.port != "80") ||
                (parsedUrl.protocol == "https:" && parsedUrl.port != "443")) {
                port = ":" + parsedUrl.port;
            }
        }
        if (!parsedUrl.pathname || parsedUrl.pathname == "")
            parsedUrl.pathname = "/";
        return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
    }
    /**
     * Normalize request parameters into a single string
     * @see https://datatracker.ietf.org/doc/html/rfc5849#section-3.4.1.3.2
     * @param parameters Object containing key-value-pairs
     * @returns A string containing all parameters for the request
     */
    static normalizeRequestParameters(parameters) {
        return OAuthHeader.makeArrayOfParameters(parameters)
            // First encode them #3.4.1.3.2 .1
            .map(value => {
            value[0] = OAuthHeader.encode(value[0]);
            value[1] = OAuthHeader.encode(value[1]);
            return value;
        })
            // Then sort them #3.4.1.3.2 .2
            .sort(OAuthHeader.requestParamSorter)
            // Then concatenate together #3.4.1.3.2 .3 & .4
            .reduce((prev, curr, index, arr) => {
            prev += curr[0];
            prev += "=";
            prev += curr[1];
            if (index < arr.length - 1)
                prev += "&";
            return prev;
        }, "");
    }
    static requestParamSorter(a, b) {
        if (a[0] == b[0]) {
            return a[1] < b[1] ? -1 : 1;
        }
        else
            return a[0] < b[0] ? -1 : 1;
    }
    /**
     * Converts an object of key-value-pairs into an array
     * @param parameters
     * @returns
     */
    static makeArrayOfParameters(parameters) {
        const pairs = [];
        Object.keys(parameters).forEach(key => {
            const value = parameters[key];
            if (Array.isArray(value)) {
                value.forEach(innerValue => {
                    pairs.push([key, innerValue]);
                });
            }
            else {
                pairs.push([key, value]);
            }
        });
        return pairs;
    }
    /**
     * Checks wether a parameter is part of th OAuth process
     * @param parameter
     * @returns True if paremeter contains oauth_ in its name
     */
    static isOAuthParameter(parameter) {
        var m = parameter.match('^oauth_');
        return m && (m[0] === "oauth_");
    }
}
exports.OAuthHeader = OAuthHeader;
OAuthHeader.seperator = ",";
//# sourceMappingURL=index.js.map