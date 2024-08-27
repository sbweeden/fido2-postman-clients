eval(globals.fidotools);

// This env var needs to be set.
var fidoutilsConfig = null;
if (pm.environment.get("fidoutilsConfig") != null) {
	fidoutilsConfig = JSON.parse(pm.environment.get("fidoutilsConfig"));
}

// It should contain a JSON document like this:
var exampleConfig = {
	"encryptionPassphrase": "MySecret",

	"origin": "https://example.ibm.com:9443",

	"fido-u2f": {
		"privateKeyHex": "00b8464b082d2a77bae48d8ec84694cd4cca7b41948635622a8db1bc87a8894f17",
		"publicKeyHex": "04ffd1d9a70f7c1c83fa8660925dfbfcbb4d1c232e5443f5d9ee4ad72480fec9d20068c05b5d7777cc25fd27d93015c0ea2d72f51d8eae1970729b98609a5013db",
		"cert": "MIIDFjCB/wIJAKiWRVc805iDMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMQ0wCwYDVQQKDAROSVNUMRMwEQYDVQQDDApVSUNDUm9vdENBMB4XDTE5MDgwNzIwMjgwM1oXDTQ2MTIyMjIwMjgwM1owNTELMAkGA1UEBhMCVVMxDTALBgNVBAoMBE5JU1QxFzAVBgNVBAMMDlVJQ0NVMkYtU0lHTkVSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/9HZpw98HIP6hmCSXfv8u00cIy5UQ/XZ7krXJID+ydIAaMBbXXd3zCX9J9kwFcDqLXL1HY6uGXBym5hgmlAT2zANBgkqhkiG9w0BAQsFAAOCAgEAKP/Ck24JM+8J7Ns4g5a8XczXPPnYe+FFs7bUQoam2sEEPBzapdIssl9rYkFKvxIW8zgPHJVIQJ3hMmq9tGkhKXT+WzIew+BJRzBYscytaaqMURHuqM1usBFQZSBUYIlDCQqezxG9bZ4cx8gzmL4ldYPGwSAex3K9XOVdyNn+ut8/axcfhDYfr0zW498KOg1L72kjthiNTrJWGaCwkfCsNNtBHWy2HmGzAgMLi7Wn3eNzTyrbzj7GBBsFm6Nv5LKLxCwX8YEd6UWzYLuP/AhAG1+w1rfPmbdi0/hXGUr8h51dlTF2DUrxQfZvECA5Du4TZHHKpTu7opI2BSVabXYp+F25RbkcE1oAqjrZeMdeWXFu5bcD5MvQ6Q3D/M1H1ngahFLzyzPprZ1OO5codyiRwhPtSyeR+FIi7yj9Lirxhv+t1pzm9N6z8DEW3Iman5+x+hGPP01n0RFP1H+Fu0jUCZfcZmx0ecrrd2r3B0YpyUR5n45dweBw+dyQZaPm0eenyMYFNuXWNx+aT7wcYFYhoYEqi0n7bGmvR3ZmFws3rBi2uLOamM1cOSnabOQ7Tvirq39TAbJ3dNZAwoD7pFn4YZHeywPGlENnij1bMnTYyVXRr/coi84bD4S147Ydm6lWpMcolpVlplbXJ3S3BDu/AqJGBqQwKtBUDuL0BbnbE+0="
	},

	"packed": {
		"aaguid": "37c4c2cf41544c5791039c9bdcca5b2b",
		"privateKeyHex": "03e158d202854c3bc0cb233a726f4445b41b4ca80b370a2c30d8fe039f820d42",
		"publicKeyHex": "045c6c82d6b47e2971a78ebbe8dd910ebbdcecb902019e6b37f743374c5740d9f0533068c562ebd7c11e55258b235efc48aba0d77f6d0ebe6f991321976ea1e072",
		"cert": "MIIDVTCCAT2gAwIBAgIJAKiWRVc805iEMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYTAlVTMQ0wCwYDVQQKDAROSVNUMRMwEQYDVQQDDApVSUNDUm9vdENBMB4XDTE5MDgwNzIwMjgwM1oXDTQ2MTIyMjIwMjgwM1owXDELMAkGA1UEBhMCVVMxDTALBgNVBAoMBE5JU1QxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEVVJQ0NQQUNLRUQtU0lHTkVSMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXGyC1rR+KXGnjrvo3ZEOu9zsuQIBnms390M3TFdA2fBTMGjFYuvXwR5VJYsjXvxIq6DXf20Ovm+ZEyGXbqHgcqMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAtsJl2cVtuRJqwm0SXhP2vGU3An79GxT1appa9JKLWz7iv5zOVWowKvbEnB6sqjNPZ1p65yEi5UmRNnkE6m6IFSRijz5eeWOHQ0ceQN4BhH9veE4Xe3WiOaahTTJX+hqj+5ByMhgw0dZ6+1iEu20BE0zKAA+VSrpA5O+LPOBDNjCfVzLI566ykNqe2mShm+UGNDYkTxVJmFXY9qyy/zLazynroE6qnIt03UutzifAnNNnBKqk9gK9C6cosDHeyvRGy9um1P21EC85yEZvN8wngzNmc8TJwnkXYHP4METHbjR9bmQP60e19a7so9sz7P5MhkFJ/JOURkbWh6qmzIGQhoNpGw6OQnAxHvkPiw9HuDEfjzIFX1LQi74uMIEG7juCIt2u56dXG7T0NM8MfVlupDJzi4AnwI+NuONrKtC5iK6HHSrRxCQ8QiPTemlymPhC/XMJW70PqDiH7cEmCbsDKg9cTN8mWCNNyb1/WkcfrP2zq+jm1Lp8Viam5kHsd66X9VP/44Aj5G6TGJU7ZitBB/hHqz0jznuZU+fRuGf2taQdCP/DXps/VngXrcvs4sRS3aid0KO5eLkUP8e11r909DMTvV/CsqghqXpS13oUbTs8cD12y93EftSbw6OKR30xcV1PScCOY/CSnCuSQFlgrXW1OotzmWQUKKKUB9Egzb8="
	},

	"packed-self": {
		"aaguid": "1811ec8b8a91459299f217f35d53242e"
	}
};

if (fidoutilsConfig == null) {
	console.log("Using default example config as there is no fidoutilsConfig environment variable set");
	fidoutilsConfig = exampleConfig;
	pm.environment.set("fidoutilsConfig", JSON.stringify(fidoutilsConfig));
}

/*
* Collection of functions useful to emulate a FIDO2 client and authenticator
*/

// CBOR encodes an object, returning results as a byte array
function myCBOREncode(o) {
	result = bytesFromArray((new Uint8Array(CBOR.encode(o))), 0, -1);
	return result;
}

// Some data structures in FIDO authenticators that are arrays of bytes
// need to be encoded as a CBOR byte string rather than a CBOR array of unsigned integers.
// Our CBOR encoder will encode Buffer to byte string, so this utility function
// is called when what we have is a byte array and what we need CBOR encoded is a byte string.
function prepareBAForCBOR(ba) {
	return (new Uint8Array(ba));
}

//
// Prepare a COSE key for CBOR encoding. Co-ordinate values are 
// required to be byte strings.
//
function prepareCOSEKeyForCBOREncoding(coseKey) {
	// create a Map, treating object keys as integers (notice call to parseInt below) and converting byte array values to 
	// a Buffer so that CBOR encoding of a COSE key results in integer keys and coordinates as byte strings
	let result = {};
	for (const [k,v] of Object.entries(coseKey)) {
		let newValue = ((v instanceof Array) ? prepareBAForCBOR(v) : v);
		result[k] = newValue;
	}
	return result;
}

/**
 * Extracts the bytes from an array beginning at index start, and continuing until
 * index end-1 or the end of the array is reached. Pass -1 for end if you want to
 * parse till the end of the array.
 */     
function bytesFromArray(o, start, end) {
        // o may be a normal array of bytes, or it could be a JSON encoded Uint8Array
        var len = o.length; 
        if (len == null) { 
                len = Object.keys(o).length;
        }       
                
        var result = [];
        for (var i = start; (end == -1 || i < end) && (i < len); i++) {
                result.push(o[i]);
        }       
        return result;
}               
                
/**             
 * Returns the bytes of a sha256 message digest of either a string or byte array
 * This is used when building the signature base string to verify registration
 * data.
 */     
function sha256(data) {
        var md = new KJUR.crypto.MessageDigest({
                alg : "sha256", 
                prov : "cryptojs" 
        });
        if (Array.isArray(data)) {
                md.updateHex(BAtohex(data));
        } else {
                md.updateString(data);
        }
        return b64toBA(hex2b64(md.digest()));
}

/**
 * Converts the bytes of an asn1-encoded X509 ceritificate or raw public key
 * into a PEM-encoded cert string
 */
function certToPEM(cert) {
	var keyType = "CERTIFICATE";
	asn1key = cert;

	if (cert != null && cert.length == 65 && cert[0] == 0x04) {
		// this is a raw public key - prefix with ASN1 metadata
		// SEQUENCE {
		// SEQUENCE {
		// OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
		// OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
		// }
		// BITSTRING <raw public key>
		// }
		// We just need to prefix it with constant 26 bytes of metadata
		asn1key = b64toBA(hextob64("3059301306072a8648ce3d020106082a8648ce3d030107034200"));
		Array.prototype.push.apply(asn1key, cert);
		keyType = "PUBLIC KEY";
	}
	var result = "-----BEGIN " + keyType + "-----\n";
	var b64cert = hextob64(BAtohex(asn1key));
	for (; b64cert.length > 64; b64cert = b64cert.slice(64)) {
		result += b64cert.slice(0, 64) + "\n";
	}
	if (b64cert.length > 0) {
		result += b64cert + "\n";
	}
	result += "-----END " + keyType + "-----\n";
	return result;
}

/**
 * Calculates the base64url of the left-most half of the sha256 hash of the octets
 * of the ASCII string str. This is how access token hashes are calculated.
 */
function atHash(str) {
	var hashBytes = sha256(b64toBA(utf8tob64(str)));
	var halfLength = Math.ceil(hashBytes.length / 2);    
	var leftSide = hashBytes.splice(0,halfLength);
	return hextob64u(BAtohex(leftSide));
}

var ENCRYPTION_keySize = 256;
var ENCRYPTION_ivSize = 128;
var ENCRYPTION_iterations = 100;
/*
 * Simple AES encryption of a payload using a passphrase
 */
function hashedEncryptAESToBA(msg, pass) {
  var salt = CryptoJS.lib.WordArray.random(ENCRYPTION_ivSize/8);

  var key = CryptoJS.PBKDF2(pass, salt, {
      keySize: ENCRYPTION_keySize/32,
      iterations: ENCRYPTION_iterations
    });

  var iv = CryptoJS.lib.WordArray.random(ENCRYPTION_ivSize/8);
  
  // sha the original text and include the b64u of the left-most bytes 
  // in what gets encrypted. This allows us to verify that decryption is correct.
  // shaStr will always be 22 chars long
  var shaStr = atHash(msg);

  
  var encrypted = CryptoJS.AES.encrypt(shaStr + msg, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC    
  });
  
  //console.log("salt: " + salt.toString());
  //console.log("iv: " + iv.toString());
  //console.log("encrypted: " + encrypted.toString());
  
  // salt, iv will be 16 bytes (ENCRYPTION_ivSize / 8) in length
  // encrypted bytes is the rest
  var saltByteArray = b64toBA(hextob64(salt.toString()));
  var ivByteArray = b64toBA(hextob64(iv.toString()));
    
  // encryption string is B64
  var encryptedByteArray = b64toBA(encrypted.toString());
  var result = [];
  result.push(...saltByteArray);
  result.push(...ivByteArray);
  result.push(...encryptedByteArray);
  return result;
}

function hashedDecryptAESFromBA(ciphertextBytes, pass) {
	var result = null;
	
  // salt, iv will be 16 bytes (ENCRYPTION_ivSize / 8) in length
  // encrypted bytes is the rest
  var saltBytes = bytesFromArray(ciphertextBytes, 0, (ENCRYPTION_ivSize / 8));
  var ivBytes = bytesFromArray(ciphertextBytes, (ENCRYPTION_ivSize / 8), 2*(ENCRYPTION_ivSize / 8));
  var encryptedBytes = bytesFromArray(ciphertextBytes, 2*(ENCRYPTION_ivSize / 8), -1);
	
  var salt = CryptoJS.enc.Hex.parse(BAtohex(saltBytes));
  var iv = CryptoJS.enc.Hex.parse(BAtohex(ivBytes));
  var encrypted = hextob64(BAtohex(encryptedBytes));
  
  //console.log("salt: " + salt.toString());
  //console.log("iv: " + iv.toString());
  //console.log("encrypted: " + encrypted);
  
  var key = CryptoJS.PBKDF2(pass, salt, {
      keySize: ENCRYPTION_keySize/32,
      iterations: ENCRYPTION_iterations
    });

  var decryptedText = CryptoJS.AES.decrypt(encrypted, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC    
  }).toString(CryptoJS.enc.Utf8);
  
  if (decryptedText != null && decryptedText.length > 22) {
	  // first 22 bytes is the left-most half of the sha256 of the rest of the msg
	  var hexShaTxt = decryptedText.substr(0,22);
	  var msg = decryptedText.substr(22);
	  
	  // validate the sha of msg
	  var computedShaStr = atHash(msg);
	  if (computedShaStr == hexShaTxt) {
		  result = msg;
	  } else {
		  console.log("decrypted sha text did not match - not encrypted by this passphrase");
	  }
  }
  
  return result;
}

function resolveCredentialIdBytesFromPrivateKeyHex(privKeyHEX) {
	if (fidoutilsConfig.encryptionPassphrase == null) {
		throw new Error("Please set the fidoutilsConfig.encryptionPassphrase environment variable");
	}
	return hashedEncryptAESToBA(hextob64(privKeyHEX), fidoutilsConfig.encryptionPassphrase);
}

function resolvePrivateKeyHexFromCredentialIdBytes(credIdBytes) {
	if (fidoutilsConfig.encryptionPassphrase == null) {
		throw new Error("Please set the fidoutilsConfig.encryptionPassphrase environment variable");
	}
	return b64tohex(hashedDecryptAESFromBA(credIdBytes, fidoutilsConfig.encryptionPassphrase));
}

/**
 * Given an attestation options response (o), return a new JSON object
 * which is a CredentialCreationOptions as defined in https://w3c.github.io/webauthn/#credentialcreationoptions-extension
 * @param o
 * @returns
 */
function attestationOptionsResponeToCredentialCreationOptions(o) {

	// the final output is a CredentialCreationOptions
	var cco = {};
	
	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
	var pkcco = {};
	
	/*
	 * required: rp, copy that 
	 */
	pkcco.rp = o.rp;
	
	/*
	 * required: user, map that to the pkcco data types
	 */
	pkcco.user = {};
	// required: id in o is base64url, but in pkcco is BufferSource
	pkcco.user.id = new Uint8Array(b64toBA(b64utob64(o.user.id)));
	// required: displayName is DOMString - copy across
	pkcco.user.displayName = o.user.displayName;
	// required: name is DOMString - copy across
	pkcco.user.name = o.user.name;
	// optional: icon - copy across if present
	if (o.user["icon"] != null) {
		pkcco.user.icon = o.user.icon;
	}		

	/*
	 * required: challenge, map to pkcco data type
	 */
	pkcco.challenge = new Uint8Array(b64toBA(b64utob64(o.challenge)));
	
	/*
	 * required: pubKeyCredParams, copy that
	 */
	pkcco.pubKeyCredParams = o.pubKeyCredParams;
	
	/*
	 * optional: timeout, copy if present
	 */
	if (o["timeout"] != null) {
		pkcco.timeout = o.timeout;
	}
	
	/*
	 * optional: excludeCredentials, map to pkcco data types if present
	 */
	if (o["excludeCredentials"] != null) {
		pkcco.excludeCredentials = [];
		for (var i = 0; i < o.excludeCredentials.length; i++) {
			var c = {};
			// required: type - copy across
			c.type = o.excludeCredentials[i].type;
			// required: id in o is base64url, but in pkcco is BufferSource
			c.id = new Uint8Array(b64toBA(b64utob64(o.excludeCredentials[i].id)));
			// optional: transports - copy across if present
			if (o.excludeCredentials[i]["transports"] != null) {
				c.transports = o.excludeCredentials[i].transports;
			}
			pkcco.excludeCredentials.push(c);
		}
	}
	
	/*
	 * optional: authenticatorSelection, copy if present
	 */
	if (o["authenticatorSelection"] != null) {
		pkcco.authenticatorSelection = o.authenticatorSelection;
	}
	
	/*
	 * optional: attestation, copy if present
	 */
	if (o["attestation"] != null) {
		pkcco.attestation = o.attestation;
	}
	
	/*
	 * optional: extensions, copy if present
	 */
	if (o["extensions"] != null) {
		pkcco.extensions = o.extensions;
	}
		
	// build final result object
	cco.publicKey = pkcco;
	return cco;
}

/*
 * Acting as the client+authenticator, prepare a FIDO2 server ServerPublicKeyCredential from a CredentialCreationOptions
 * See example at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#example-authenticator-attestation-response
 * Schema at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverpublickeycredential
 */
function processCredentialCreationOptions(cco, attestationFormat = 'none', up = true, uv = true) {
	var spkc = {};
	
	// the ServerAuthenticatorAttestationResponse
	var saar = {};
		
	// build the clientDataJSON
	var clientDataJSON = {
			"origin": fidoutilsConfig.origin,
			"challenge": hextob64u(BAtohex(bytesFromArray(cco.publicKey.challenge,0,-1))),
			"type": "webauthn.create"
	};
		
	// add the base64url of this stringified JSON to the response 
	saar.clientDataJSON = utf8tob64u(JSON.stringify(clientDataJSON));
	
	// also compute the hash - most attestation types need it as part of data to sign
	var clientDataHash = sha256(b64toBA(utf8tob64(JSON.stringify(clientDataJSON))));

	// attestation object see: https://w3c.github.io/webauthn/#sctn-attestation

	// Build the authenticatorData
	var authData = [];
	
	// first rpIdHashBytes
	authData.push(...sha256(cco.publicKey.rp.id));
	
	/* 
	 * flags 
	 *  - conditionally set UV, UP and indicate attested credential data is present
	 *  - Note we never set UV for fido-u2f
	 */
	var flags = (up ? 0x01 : 0x00) | ((uv && attestationFormat != 'fido-u2f') ? 0x04 : 0x00) | 0x40;
	authData.push(flags);
	
	// add 4 bytes of counter - we use time in epoch seconds as monotonic counter
	var now = (new Date()).getTime() / 1000;
	authData.push(
			((now & 0xFF000000) >> 24) & 0xFF,
			((now & 0x00FF0000) >> 16) & 0xFF,
			((now & 0x0000FF00) >> 8) & 0xFF,
			(now & 0x000000FF));
	
	// attestedCredentialData
	var attestedCredentialData = [];

	// aaguid - 16 bytes, if we have one defined use it, otherwise all zeros

	var aaguid = ((fidoutilsConfig[attestationFormat] == null || fidoutilsConfig[attestationFormat].aaguid == null) ? null : b64toBA(hextob64(fidoutilsConfig[attestationFormat].aaguid.replace(/-/g,""))));
	if (aaguid == null) {
		aaguid = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
	}
	attestedCredentialData.push(...aaguid);

	// based on the attestationFormat, we use some different attestation keys
	
	// we use the ECDSA key for the registered keypair - generate a new keypair now
	var keypair = KEYUTIL.generateKeypair("EC", "prime256v1");
	
	//
	// map the private key to a credential id - this is just one way to do it with key wrapping
	// you could also locally store the private key and index with any credentialId handle you like
	//
	var credIdBytes = resolveCredentialIdBytesFromPrivateKeyHex(keypair.prvKeyObj.prvKeyHex);
	
	// COSE format of the EC256 key
	var credPublicKeyCOSE = {
			"1":2,  // kty
			"3":-7, // alg
			"-1":1, // crv
			"-2": b64toBA(hextob64(keypair.pubKeyObj.getPublicKeyXYHex()["x"])), // xCoordinate
			"-3": b64toBA(hextob64(keypair.pubKeyObj.getPublicKeyXYHex()["y"])) // yCoordinate
	};
	
	// credentialIdLength (2 bytes) and credential Id
	var lenArray = [ (credIdBytes.length - (credIdBytes.length & 0xFF)) / 256, credIdBytes.length & 0xFF];
	attestedCredentialData.push(...lenArray);
	attestedCredentialData.push(...credIdBytes);
	
	// credential public key - take bytes from CBOR encoded COSE key
	var credPublicKeyBytes = myCBOREncode(prepareCOSEKeyForCBOREncoding(credPublicKeyCOSE));
	attestedCredentialData.push(...credPublicKeyBytes);
	
	// add attestedCredentialData to authData
	authData.push(...attestedCredentialData);
	
	// build attestation statement depending on requested format
	var attStmt = null;
	if (attestationFormat == 'none') {
		// for none, just return an empty attStmt
		attStmt = {};
	} else if (attestationFormat == 'fido-u2f') {
		attStmt = buildFidoU2FAttestationStatement(keypair, clientDataHash, authData, credIdBytes);
	} else if (attestationFormat == 'packed') {
		attStmt = buildPackedAttestationStatement(keypair, clientDataHash, authData, credIdBytes, false);
	} else if (attestationFormat == 'packed-self') {
		attStmt = buildPackedAttestationStatement(keypair, clientDataHash, authData, credIdBytes, true);
		// this is really packed, we only used packed-self internally to toggle the flag above
		attestationFormat = 'packed';
	} else {
		throw ("Unsupported attestationFormat: " + attestationFormat);
	}
	
	// build the attestationObject
	var attestationObject = {"fmt": attestationFormat, "attStmt": attStmt, "authData": prepareBAForCBOR(authData) };
	
	
	// add the base64url of the CBOR encoding of the attestationObject to the response
	
	saar.attestationObject = hextob64u(BAtohex(myCBOREncode(attestationObject)));
	
	// construct ServerPublicKeyCredential fields
		
	// id is base64url encoding of the credId
	spkc.id = hextob64u(BAtohex(credIdBytes));
	
	// rawId is the same as id
	spkc.rawId = spkc.id;
	
	// response - this is the meat of the data structure, contain the clientDataJSON and attestation
	spkc.response = saar;

	// type (from Credential defined here: https://w3c.github.io/webappsec-credential-management/#credential)
	spkc.type = "public-key";

	// extension results - for now we populate as empty map
	spkc.getClientExtensionResults = {};
	
	return spkc;
}





/**
 * Given an assertion options response (o), return a new JSON object
 * which is a CredentialRequestOptions as defined in https://w3c.github.io/webauthn/#credentialrequestoptions-extension
 * @param o
 * @returns
 */
function assertionOptionsResponeToCredentialRequestOptions(o) {

	// the final output is a CredentialRequestOptions
	var cro = {};
	
	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
	var pkcro = {};
	
	/*
	 * required: challenge, map to pkcro data type
	 */
	pkcro.challenge = new Uint8Array(b64toBA(b64utob64(o.challenge)));

	/*
	 * optional: timeout, copy if present
	 */
	if (o["timeout"] != null) {
		pkcro.timeout = o.timeout;
	}
	
	/*
	 * optional rpId: If not present, needs to be defaulted to origin's effective domain. 
	 * We should always have it, because we supply as part of our server implementation.
	 */
	if (o["rpId"] != null) {
		pkcro.rpId = o.rpId;
	}
	
	/*
	 * optional allowCredentials, map to pkcco data types if present
	 */
	if (o["allowCredentials"] != null) {
		pkcro.allowCredentials = [];
		for (var i = 0; i < o.allowCredentials.length; i++) {
			var c = {};
			// required: type - copy across
			c.type = o.allowCredentials[i].type;
			// required: id in o is base64url, but in pkcco is BufferSource
			c.id = new Uint8Array(b64toBA(b64utob64(o.allowCredentials[i].id)));
			// optional: transports - copy across if present
			if (o.allowCredentials[i]["transports"] != null) {
				c.transports = o.allowCredentials[i].transports;
			}
			pkcro.allowCredentials.push(c);
		}
	}
	
	/*
	 * optional: userVerification, copy if present
	 */
	if (o["userVerification"] != null) {
		pkcro.userVerification = o.userVerification;
	}
	
	/*
	 * optional: extensions, copy if present
	 */
	if (o["extensions"] != null) {
		pkcro.extensions = o.extensions;
	}
	
	// build final result object
	cro.publicKey = pkcro;
	return cro;	
}



/*
 * Acting as the client+authenticator, prepare a FIDO2 server ServerAuthenticatorAssertionResponse from a CredentialRequestOptions
 * See example at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#authentication-examples
 * Schema at: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html#serverauthenticatorassertionresponse
 *
 * cro is required.
 * The payloadHash is an extension that we added for an IoT demo, and outside that context can be passed as null.
 */
function processCredentialRequestOptions(cro, up = true, uv = true, payloadHash = null) {
	
	// ServerPublicKeyCredential
	var spkc = {};
	
	// the ServerAuthenticatorAssertionResponse
	var saar = {};
		
	// build the clientDataJSON
	var clientDataJSON = {
			"origin": fidoutilsConfig.origin,
			"challenge": hextob64u(BAtohex(bytesFromArray(cro.publicKey.challenge,0,-1))),
			"type": "webauthn.get"
	};

	if (payloadHash != null) {
		clientDataJSON.payloadHash = payloadHash;
	}
	
	// attestation object see: https://w3c.github.io/webauthn/#sctn-attestation
	
	// add the base64url of this stringified JSON to the response 
	saar.clientDataJSON = utf8tob64u(JSON.stringify(clientDataJSON));
	
	// Build the authenticatorData
	var authData = [];
	
	// first rpIdHashBytes
	authData.push(...sha256(cro.publicKey.rpId));
	
	// flags - UP, UV
	var flags = (up ? 0x01 : 0x00) | (uv ? 0x04 : 0x00);
	authData.push(flags);
	
	// add 4 bytes of signature counter - we use the current time in epoch seconds as the monotonic counter
	var now = (new Date()).getTime() / 1000;
	authData.push(
			((now & 0xFF000000) >> 24) & 0xFF,
			((now & 0x00FF0000) >> 16) & 0xFF,
			((now & 0x0000FF00) >> 8) & 0xFF,
			(now & 0x000000FF));
	
	// add authData to ServerAuthenticatorAssertionResponse
	saar.authenticatorData = hextob64u(BAtohex(authData));

	// use the credential id to resolve the private key
	var privKeyHex = null;
	var usedCredentialId = null;
	var usernameLessFlow = false;
	if (cro.publicKey["allowCredentials"] != null && cro.publicKey["allowCredentials"].length > 0) {
		for (var i = 0; i < cro.publicKey["allowCredentials"].length && privKeyHex == null; i++) {
			var candidateCredIdBytes = bytesFromArray(cro.publicKey["allowCredentials"][i].id, 0, -1);
			var candidateCredIdStr =hextob64u(BAtohex(candidateCredIdBytes));
			try { 
				var candidatePrivKeyHex = resolvePrivateKeyHexFromCredentialIdBytes(candidateCredIdBytes);
				if (candidatePrivKeyHex != null) {
					usedCredentialId = candidateCredIdStr;
					privKeyHex = candidatePrivKeyHex;
					
					//
					// store these as the "last used" credential id and privKeyHex as well, so that
					// we can simulate a username-less flow in a different options/results pair.					
					//
					pm.environment.set("last_CredentialId", usedCredentialId);
					pm.environment.set("last_privKeyHex", privKeyHex);
				}
			} catch (e) {
				// probably not our cred id
				console.log("Ignoring allowCredentials cred id as we could not decrypt it: " + candidateCredIdStr);
			}
		}
	} else {
		//
		// If there is a stored last_CredentialId and last_privKeyHex, re-use those for this 
		// username-less login flow.
		//
		usernameLessFlow = true;
		usedCredentialId = pm.environment.get("last_CredentialId");
		privKeyHex = pm.environment.get("last_privKeyHex");
	}
	
	if (privKeyHex != null) {
		// credential information
		var ecdsa = new KJUR.crypto.ECDSA({'curve': 'prime256v1'});
		ecdsa.setPrivateKeyHex(privKeyHex);
		//ecdsa.setPublicKeyHex(EC_PUBLIC_KEY_HEX);
		
		// compute the signature
		var cHash = sha256(b64toBA(b64utob64(saar.clientDataJSON)));
		var sigBase = [];
		sigBase.push(...authData);
		sigBase.push(...cHash);
		
		var sig = new KJUR.crypto.Signature({"alg": "SHA256withRSA"});
		sig.init(ecdsa);
		sig.updateHex(BAtohex(sigBase));
		var sigValueHex = sig.sign();
		
		saar.signature = hextob64u(sigValueHex);
		
		// add the user handle for username-less flows
		if (usernameLessFlow) {
			// we get the user handle from the most recent attestation options response
			console.log("Retrieving cco for username-less login flow");
			var cco = JSON.parse(pm.environment.get("cco"));
			console.log("Retrieved cco: " + JSON.stringify(cco));
			saar.userHandle = hextob64u(BAtohex(bytesFromArray(cco.publicKey.user.id,0,-1)));
			console.log("Username-less login flow userHandle: " + saar.userHandle);
		} else {
			saar.userHandle = "";
		}
		
		// construct ServerPublicKeyCredential fields
		
		// id of credential we used
		spkc.id = usedCredentialId;
		
		// rawId is the same as id
		spkc.rawId = spkc.id;
		
		// response - this is the meat of the data structure, contain the clientDataJSON, authenticatorData, signature and userHandle
		spkc.response = saar;
	
		// type (from Credential defined here: https://w3c.github.io/webappsec-credential-management/#credential)
		spkc.type = "public-key";
	
		// extension results - for now we populate as empty map
		spkc.getClientExtensionResults = {};
	} else {
		// error
		throw new Error("Assertion options allowCredentials list did not contain any credential id known to the POSTMAN software authenticator");
		spkc = null;
	}
	
	return spkc;
}


function buildFidoU2FAttestationStatement(keypair, clientDataHash, authData, credIdBytes) {
	var attStmt = {};
	
	var ecdsa = new KJUR.crypto.ECDSA({'curve': 'prime256v1'});
	ecdsa.setPrivateKeyHex(fidoutilsConfig["fido-u2f"].privateKeyHex.replace(/:/g,""));
	ecdsa.setPublicKeyHex(fidoutilsConfig["fido-u2f"].publicKeyHex.replace(/:/g,""));

	var attestationCert = new X509();
	attestationCert.readCertPEM(certToPEM(b64toBA(fidoutilsConfig["fido-u2f"].cert)));

	// populate x5c of attStmt with one entry - the bytes of the self-signed attestation cert 
	attStmt.x5c = [ prepareBAForCBOR(b64toBA(hextob64(attestationCert.hex))) ];
	
	// build sigBase
	var rpidhashBytes = bytesFromArray(authData, 0, 32);
	var sigBase = [ 0x00 ].concat(
			rpidhashBytes, clientDataHash,
			credIdBytes, b64toBA(hextob64(keypair.pubKeyObj.pubKeyHex)));
	
	// generate and populate signature (the sigBase is signed with the attestation cert)
	var sig = new KJUR.crypto.Signature({"alg": "SHA256withRSA"});
	sig.init(ecdsa);
	sig.updateHex(BAtohex(sigBase));
	var sigValueHex = sig.sign();

	attStmt.sig = prepareBAForCBOR(b64toBA(hextob64(sigValueHex)));
	return attStmt;
}



function buildPackedAttestationStatement(keypair, clientDataHash, authData, credIdBytes, useSelfAttestation) {
	
	/* 
	 * we only support ECDSA256 at the moment
	 */
	var attStmt = { alg: -7 };
	
	var ecdsa = new KJUR.crypto.ECDSA({'curve': 'prime256v1'});

	// toggle to decide whether to sign with credential private key or attestation private key
	if (useSelfAttestation) {
		ecdsa.setPrivateKeyHex(keypair.prvKeyObj.prvKeyHex);
		ecdsa.setPublicKeyHex(keypair.pubKeyObj.pubKeyHex);
	} else {
		ecdsa.setPrivateKeyHex(fidoutilsConfig.packed.privateKeyHex.replace(/:/g,""));
		ecdsa.setPublicKeyHex(fidoutilsConfig.packed.publicKeyHex.replace(/:/g,""));

		// if not using self attestation, include the attestation cert as x5c
		var attestationCert = new X509();
		attestationCert.readCertPEM(certToPEM(b64toBA(fidoutilsConfig.packed.cert)));
		attStmt.x5c = [ prepareBAForCBOR(b64toBA(hextob64(attestationCert.hex))) ];
	}
	
	
	// build sigBase
	var sigBase = authData.concat(clientDataHash);
	
	// generate and populate signature (the sigBase is signed with the attestation cert)
	var sig = new KJUR.crypto.Signature({"alg": "SHA256withRSA"});
	sig.init(ecdsa);
	sig.updateHex(BAtohex(sigBase));
	var sigValueHex = sig.sign();

	attStmt.sig = prepareBAForCBOR(b64toBA(hextob64(sigValueHex)));
	return attStmt;
}

function generateRandom(len) {
    // generates a random string of alpha-numerics
    var chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var result = "";
    for (var i = 0; i < len; i++) {
            result = result + chars.charAt(Math.floor(Math.random()*chars.length));
    }
    return result;
}
