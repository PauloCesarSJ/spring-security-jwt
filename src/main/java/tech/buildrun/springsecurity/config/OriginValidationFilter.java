package tech.buildrun.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class OriginValidationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(OriginValidationFilter.class);

    private final List<String> allowedOrigins;
    private final List<String> sensitiveEndpoints = Arrays.asList("/users", "/login");

    public OriginValidationFilter(String[] allowedOrigins) {
        this.allowedOrigins = Arrays.asList(allowedOrigins);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String origin = request.getHeader("Origin");
        String path = request.getRequestURI();

        // Apenas validar origens para endpoints sensíveis
        if (origin != null && sensitiveEndpoints.stream().anyMatch(path::contains)) {
            if (!allowedOrigins.contains(origin)) {
                logger.warn("Tentativa de acesso de origem não permitida: {} para endpoint: {}", origin, path);
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Origem não permitida");
                return;
            }

            // Adicionar header para proteção contra clickjacking
            response.setHeader("X-Frame-Options", "DENY");
            response.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
        }

        filterChain.doFilter(request, response);
    }
}