package br.com.cya.security.service;

import br.com.cya.security.security.UserDetailsImpl;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;

@Service
public class JwtTokenService {

    private static final String SECRET_KEY = "075561e94b2cf729f9681465e05432f8ee3bf4402c7ab6cc330eec46eeb1e7b5";
    private static final String ISSUER = "cya-api";
    private final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

    // Responsável por gerar o token JWT
    public String generateToken(UserDetailsImpl userDetails) {
        try {
            return JWT.create()
                    .withIssuer(ISSUER)
                    .withSubject(userDetails.getUsername())
                    .withIssuedAt(creationDate())
                    .withExpiresAt(expirationDate())
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            throw new JWTCreationException("Erro ao gerar token JWT.", e);
        }
    }

    // Responsável por resgatar o usuário (subject) do token JWT
    public String getUsernameByToken(String token) {
        try {
            return JWT.require(algorithm)
                .withIssuer(ISSUER)
                .build()
                .verify(token)
                .getSubject();
        } catch (JWTVerificationException e) {
            throw new JWTVerificationException("Token inválido ou expirado.");
        }
    }

    private Instant creationDate() {
        return ZonedDateTime.now(ZoneId.of("America/Sao_Paulo")).toInstant();
    }

    private Instant expirationDate() {
        return ZonedDateTime.now(ZoneId.of("America/Sao_Paulo")).plusHours(8).toInstant();
    }
}
