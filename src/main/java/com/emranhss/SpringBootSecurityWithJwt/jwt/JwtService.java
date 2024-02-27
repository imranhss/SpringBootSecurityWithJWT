package com.emranhss.SpringBootSecurityWithJwt.jwt;


import com.emranhss.SpringBootSecurityWithJwt.model.User;
import com.emranhss.SpringBootSecurityWithJwt.repository.ITokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {
    private final ITokenRepository tokenRepository;

    private final String SECREAT_KEY = "d169552a202ace4ed9b31a326df08a2aa723e197a10213030f7c4be596ba99b6";



    // Extracts username from JWT token
    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    // Checks if the token is expired
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extracts expiration date from the token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    // Validates whether the token is valid for a given user
    public boolean isValid(String token, UserDetails user) {
        String username = extractUsername(token);

        // Check if the token is valid and not expired
        boolean validToken = tokenRepository
                .findByToken(token)
                .map(t -> !t.isLoggedOut())
                .orElse(false);

        return (username.equals(user.getUsername())) && !isTokenExpired(token) && validToken;
    }

    // Extracts a specific claim from the token's claims
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    // Parses and verifies the token to extract all claims
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

    }

    // Retrieves the signing key used for JWT signing and verification
    private SecretKey getSigninKey() {

        byte[] keyBytes = Decoders.BASE64URL.decode(SECREAT_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }



    // Method signature indicating that this method generates a token for a given user.
    public String generateToken(User user) {

        // Building a JWT (JSON Web Token) using the JwtBuilder class.
        String token = Jwts
                .builder()

                // Setting the subject of the token to the user's email address.
                .subject(user.getEmail())

                // Setting the timestamp when the token was issued to the current time.
                .issuedAt(new Date(System.currentTimeMillis()))

                // Setting the expiration time of the token to 24 hours from the current time.
                .expiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))

                // Signing the token with a signing key obtained from a method called getSigninKey().
                .signWith(getSigninKey())

                // Compacting the token into its final string representation.
                .compact();

        // Returning the generated token.
        return token;

    }



//    public String generateToken(User user) {
//
//        String token = Jwts
//                .builder()
//                .subject(user.getEmail())
//                .issuedAt(new Date(System.currentTimeMillis()))
//                .expiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000))
//                .signWith(getSigninKey())
//                .compact();
//
//        return token;
//
//    }


}
