## Encrypt & Decrypt specific parts of your JSON using GatewayScript

If you're using IBM DataPower Gateway and need to _asymmetric_ encrypt or decrypt just a part of a json object, it might be complicated. This two GatewayScripts will assist you doing that with a minimal effort.

## How to use it?

Just drop them on your processing rule, configure the relevant parameters and you're good to go.

## Encryption Parameters (for jwe-encrypt.js)

*   **certificate:** a name of a valid Crypto Certificate object to be used for the encryption.
*   **encAlg:** The JWE encryption algorithm. supported values are:  
    \- A128CBC-HS256 (default)  
    \- A192CBC-HS384  
    \- A256CBC-HS512  
    \- A128GCM  
    \- A192GCM  
    \- A256GCM
*   **keyMgmtAlg:** The JWE key management algorithm. supported values are:  
    \- RSA1\_5 (default)  
    \- RSA-OAEP  
    \- RSA-OAEP-256
*   **outputFormat:** The JWE encryption output format. supported values are:  
    \- compact (default)  
    \- json  
    \- json\_flat
*   **fields:** Comma separated values of the field-names you want to encrypt.

## Decryption Parameters (for jwe-decrypt.js)

*   **key:** a name of a valid Crypto Key object to be used for the decryption.
*   **encAlg:** The JWE encryption algorithm. supported values are:  
    \- A128CBC-HS256 (default)  
    \- A192CBC-HS384  
    \- A256CBC-HS512  
    \- A128GCM  
    \- A192GCM  
    \- A256GCM
*   **keyMgmtAlg:** The JWE key management algorithm. supported values are:  
    \- RSA1\_5 (default)  
    \- RSA-OAEP  
    \- RSA-OAEP-256
*   **inputFormat:** The JWE decryption input format. supported values are:  
    \- compact (default)  
    \- json  
    \- json\_flat
*   **fields:** Comma separated values of the field-names you want to decrypt.
