# OAuth Header

Generates the value for the Authorization header when making request via OAuth 1.

## Motivation
When trying to write a client for an API which utilizes OAuth 1, I ran into the problem
that there are only packages which are either doing to much or not enough for my taste:

[node-oauth](https://github.com/ciaranj/node-oauth) provides a full http client that I
have to use to make my requests.

[oauth-signature](https://github.com/bettiolo/oauth-signature-js) only generates the
signature and one has to assemble the header manually. Also at the time of writing I
was unable to create a valid signature with this package (tested against [Postman](https://www.postman.com/))

So I set out to create a solution that sits in the middle: Only take care of what's needed
for the authentification and leave the rest to the dev.

## Installation
To install this package use 
`npm i oauth-header`

The package also contains type definitions for use with TypeScript.

## Usage

```
const oauthHeader = require("oauth-header);
const generator = new oauthHeader.Generator(
    "consumerKey",
    "consumerSecret",
    "tokenKey",
    "tokenSecret"
);
const value = generator.generateHeaderValue(
    "GET",
    "https://example.com"
);

console.log(value);
// OAuth oauth_consumer_key="consumerKey",oauth_nonce="1C107D6C84061269",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1638119811",oauth_token="tokenKey",oauth_version="1.0",oauth_signature="pLm0aUMcISV%2Bow0U%2BwhWdkf4lVk%3D"
```

### Options

To account for differenc signing methods `Generator.generateHeaderValue()` accepts the additional parameter `signatureMethod`, which can be one of three options:

* `PLAINTEXT`
* `HMAC-SHA1`
* `RSA-SHA1`

## Constraints

At the time of writing this package is highly geared towards my personal use case and may not work for yours.

### Application Token
Currently the application token is mandatory.

### Signing Methods
The signing with the `RSA-SHA1` algorithm is not implemented yet.

### GET Parameters
Currently the package does not support processing complex parameters i.e. objects. Only basic values as string, numbers, booleans may be used.

## Licences
Part of the source code is based on [node-oauth](https://github.com/ciaranj/node-oauth) and [oauth-signature](https://github.com/bettiolo/oauth-signature-js). Their respective licences can be found in the [licence folder](https://github.com/saenglert/oauth-header/blob/master/licences).