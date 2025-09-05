package tech.buildrun.springsecurity.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tech.buildrun.springsecurity.controller.dto.LoginRequest;
import tech.buildrun.springsecurity.controller.dto.LoginResponse;
import tech.buildrun.springsecurity.entities.Role;
import tech.buildrun.springsecurity.repository.UserRepository;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@RestController
public class TokenController {

    private static final Logger logger = LoggerFactory.getLogger(TokenController.class);

    private final JwtEncoder jwtEncoder;
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final CacheManager cacheManager;

    @Value("${jwt.expiration:3600}")
    private Long expiration;

    @Value("${jwt.issuer:mybackend}")
    private String issuer;

    @Value("${jwt.audience:myapp}")
    private String audience;

    @Value("${security.rate-limit.login.attempts:5}")
    private int maxLoginAttempts;

    @Value("${security.rate-limit.login.interval:300000}")
    private long loginIntervalMs;

    private static final String LOGIN_ATTEMPTS_CACHE = "loginAttempts";

    public TokenController(JwtEncoder jwtEncoder,
                           UserRepository userRepository,
                           BCryptPasswordEncoder passwordEncoder,
                           CacheManager cacheManager) {
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.cacheManager = cacheManager;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest,
                                               HttpServletRequest request) {

        String clientIP = getClientIP(request);
        String username = loginRequest.username();

        // Verificar rate limiting por IP
        if (isRateLimited(clientIP, "ip")) {
            logger.warn("Rate limit excedido para IP: {}", clientIP);
            return createRateLimitResponse(clientIP, "ip");
        }

        // Verificar rate limiting por username
        if (isRateLimited(username, "user")) {
            logger.warn("Rate limit excedido para usuário: {}", username);
            return createRateLimitResponse(username, "user");
        }

        // Pequeno delay para evitar timing attacks
        try {
            Thread.sleep(100 + (long) (Math.random() * 100));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        var user = userRepository.findByUsername(username);

        if (user.isEmpty() || !user.get().isLoginCorrect(loginRequest, passwordEncoder)) {
            incrementLoginAttempts(clientIP, username);
            logger.warn("Tentativa de login inválida para usuário: {}", username);
            throw new BadCredentialsException("Credenciais inválidas");
        }

        // Login bem-sucedido - resetar contadores
        resetLoginAttempts(clientIP, username);

        var now = Instant.now();
        var userEntity = user.get();

        var scopes = userEntity.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.joining(" "));

        var claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(Collections.singletonList(audience))
                .subject(userEntity.getUserId().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiration))
                .claim("scope", scopes)
                .claim("username", userEntity.getUsername())
                .build();

        var jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return ResponseEntity.ok(new LoginResponse(jwtValue, expiration));
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    private boolean isRateLimited(String key, String type) {
        String cacheKey = type + ":" + key;
        Cache cache = cacheManager.getCache(LOGIN_ATTEMPTS_CACHE);

        if (cache != null) {
            AtomicInteger attempts = cache.get(cacheKey, AtomicInteger.class);
            return attempts != null && attempts.get() >= maxLoginAttempts;
        }
        return false;
    }

    private void incrementLoginAttempts(String ip, String username) {
        incrementAttempts("ip:" + ip);
        incrementAttempts("user:" + username);
    }

    private void incrementAttempts(String cacheKey) {
        Cache cache = cacheManager.getCache(LOGIN_ATTEMPTS_CACHE);
        if (cache != null) {
            AtomicInteger attempts = cache.get(cacheKey, AtomicInteger.class);
            if (attempts == null) {
                attempts = new AtomicInteger(0);
            }
            cache.put(cacheKey, new AtomicInteger(attempts.incrementAndGet()));
        }
    }

    private void resetLoginAttempts(String ip, String username) {
        resetAttempts("ip:" + ip);
        resetAttempts("user:" + username);
    }

    private void resetAttempts(String cacheKey) {
        Cache cache = cacheManager.getCache(LOGIN_ATTEMPTS_CACHE);
        if (cache != null) {
            cache.evict(cacheKey);
        }
    }

    private ResponseEntity<LoginResponse> createRateLimitResponse(String key, String type) {
        String cacheKey = type + ":" + key;
        Cache cache = cacheManager.getCache(LOGIN_ATTEMPTS_CACHE);

        int remainingAttempts = 0;
        if (cache != null) {
            AtomicInteger attempts = cache.get(cacheKey, AtomicInteger.class);
            if (attempts != null) {
                remainingAttempts = Math.max(0, maxLoginAttempts - attempts.get());
            }
        }

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("X-RateLimit-Limit", String.valueOf(maxLoginAttempts))
                .header("X-RateLimit-Remaining", String.valueOf(remainingAttempts))
                .header("X-RateLimit-Reset", String.valueOf(System.currentTimeMillis() + loginIntervalMs))
                .build();
    }
}