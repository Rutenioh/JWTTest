package es.uxxi.jwt;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * 
 * Ejemplo sacado de:
 * 
 * https://antoniogoncalves.org/2016/10/03/securing-jax-rs-endpoints-with-jwt/
 * 
 * @author hectorg
 *
 */
class JWTTest {

	
	
	
	private String secretKey = "S3Cr3T_K3y_1mP0S1bL3_D3_4d1v1N4R";

	@Test
	void testCrearTokenYValidar() {

		Key signingKey = new SecretKeySpec(secretKey.getBytes(),
				SignatureAlgorithm.HS256.getJcaName());

		Date expDate = new Date(System.currentTimeMillis() + 100000);

		String jwtString = Jwts.builder().setIssuer("kermit").setSubject("Joe").setIssuedAt(new Date())
				.setExpiration(expDate).signWith(signingKey, SignatureAlgorithm.HS256).compact();

		System.out.println(jwtString);

		Key testKey = new SecretKeySpec(secretKey.getBytes(),
				SignatureAlgorithm.HS256.getJcaName());
		Jwts.parser().setSigningKey(testKey).parseClaimsJws(jwtString);

		System.out.println("Token valid");
	}

	@Test
	void testCrearTokenYQueExpire() throws InterruptedException {
		
		Key signingKey = new SecretKeySpec(secretKey.getBytes(),
				SignatureAlgorithm.HS256.getJcaName());

		Date expDate = new Date(System.currentTimeMillis() + 100);

		String jwtString = Jwts.builder().setIssuer("kermit").setSubject("Joe").setIssuedAt(new Date())
				.setExpiration(expDate).signWith(signingKey, SignatureAlgorithm.HS256).compact();

		System.out.println(jwtString);

		// Experamos un segundo para que de error en la validación
		Thread.sleep(1000);

		Key testKey = new SecretKeySpec(secretKey.getBytes(),
				SignatureAlgorithm.HS256.getJcaName());
		
		
		assertThrows(ExpiredJwtException.class, () -> Jwts.parser().setSigningKey(testKey).parseClaimsJws(jwtString));

		
	}

}
