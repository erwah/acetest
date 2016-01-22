package se.wahlstromstekniska.acetest.authorizationserver;

import java.util.Arrays;
import java.util.List;

import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

public class JWT {

	public String generateJWT(EllipticCurveJsonWebKey signingKey, String aud) throws Exception {
	    //
	    // JSON Web Token is a compact URL-safe means of representing claims/attributes to be transferred between two parties.
	    // This example demonstrates producing and consuming a signed JWT
	    //

	    // Give the JWK a Key ID (kid), which is just the polite thing to do
	    signingKey.setKeyId("k1");

	    // Create the Claims, which will be the content of the JWT
	    JwtClaims claims = new JwtClaims();
	    claims.setAudience(aud); // to whom the token is intended to be sent
	    claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
	    claims.setGeneratedJwtId(); // a unique identifier for the token
	    claims.setIssuedAtToNow();  // when the token was issued/created (now)
	    claims.setSubject("subject"); // the subject/principal is whom the token is about
	    claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
	    List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
	    claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array

	    // A JWT is a JWS and/or a JWE with JSON claims as the payload.
	    // In this example it is a JWS so we create a JsonWebSignature object.
	    JsonWebSignature jws = new JsonWebSignature();

	    // The payload of the JWS is JSON content of the JWT Claims
	    jws.setPayload(claims.toJson());

	    // The JWT is signed using the private key
	    jws.setKey(signingKey.getPrivateKey());

	    // Set the Key ID (kid) header because it's just the polite thing to do.
	    // We only have one key in this example but a using a Key ID helps
	    // facilitate a smooth key rollover process
	    jws.setKeyIdHeaderValue(signingKey.getKeyId());

	    // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
	    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

	    // Sign the JWS and produce the compact serialization or the complete JWT/JWS
	    // representation, which is a string consisting of three dot ('.') separated
	    // base64url-encoded parts in the form Header.Payload.Signature
	    // If you wanted to encrypt it, you can simply set this jwt as the payload
	    // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
	    String jwt = jws.getCompactSerialization();


	    // Now you can do something with the JWT. Like send it to some other party
	    // over the clouds and through the interwebs.
	    System.out.println("JWT: " + jwt);

	    return jwt;
	}
	

}
