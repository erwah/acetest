package se.wahlstromstekniska.acetest.authorizationserver;

import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

public class JWT {

	public String generateJWT(EllipticCurveJsonWebKey signingKey, String aud, JsonWebKey clientsPublicKey) throws Exception {

	    // add the claims for aud, issuedAt
	    JwtClaims claims = new JwtClaims();
	    claims.setAudience(aud); // to whom the token is intended to be sent
	    claims.setGeneratedJwtId(); // a unique identifier for the token
	    claims.setIssuedAtToNow();  // when the token was issued/created (now)

	    JsonWebSignature jws = new JsonWebSignature();

	    String claimsJson = claims.toJson();

	    String cnf = "\"cnf\": {\"jwk\":" + clientsPublicKey.toJson(OutputControlLevel.PUBLIC_ONLY) + "}";
	    // TODO: this is just a quick fix to handle objects in JwtClaims. Remove scary parsing.
	    
	    // remove last } sign
	    claimsJson = claimsJson.substring(0, claimsJson.length()-1);
	    
	    // add cnf and add back the }
	    claimsJson += ", " + cnf + "}"; 

	    // set payload
	    jws.setPayload(claimsJson);

	    // JWT should be signed with AS private key
	    jws.setKey(signingKey.getPrivateKey());

	    jws.setKeyIdHeaderValue(signingKey.getKeyId());

	    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

	    // Sign and return the JWS
	    return jws.getCompactSerialization();
	}
	
	
}
