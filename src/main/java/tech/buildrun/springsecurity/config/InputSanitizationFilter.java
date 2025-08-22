package tech.buildrun.springsecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.util.regex.Pattern;

public class InputSanitizationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(InputSanitizationFilter.class);
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i).*\\b(union|select|insert|update|delete|drop|alter|create|exec|xp_cmdshell|--|;|\\*|%27|%20|%00|%0a|%0d|%3b|%3c|%3e)\\b.*"
    );

    private final PolicyFactory htmlSanitizer = new HtmlPolicyBuilder()
            .allowElements("a", "b", "i", "em", "strong", "p", "br")
            .allowUrlProtocols("http", "https")
            .allowAttributes("href").onElements("a")
            .requireRelNofollowOnLinks()
            .toFactory();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Verificar se há tentativas de SQL Injection nos parâmetros
        boolean hasSqlInjection = request.getParameterMap().values().stream()
                .flatMap(java.util.Arrays::stream)
                .anyMatch(value -> SQL_INJECTION_PATTERN.matcher(value).matches());

        if (hasSqlInjection) {
            logger.warn("Tentativa de SQL Injection detectada de: {}", request.getRemoteAddr());
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Entrada inválida");
            return;
        }

        // Continuar com a cadeia de filtros
        filterChain.doFilter(request, response);
    }

    public String sanitizeHtml(String input) {
        return htmlSanitizer.sanitize(input);
    }
}