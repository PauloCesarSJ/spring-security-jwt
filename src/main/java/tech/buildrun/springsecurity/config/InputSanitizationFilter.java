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
import org.springframework.web.util.HtmlUtils;

import java.io.IOException;
import java.util.regex.Pattern;

public class InputSanitizationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(InputSanitizationFilter.class);

    // Padrão melhorado para detectar SQL Injection
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i)(\\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|DECLARE|TRUNCATE|CALL|XP_|SP_)\\b|\\b(OR|AND)\\b\\s*[=<>]|--|;|/\\*|\\*/|@@|@|#|\\$|%27|%20|%00|%0a|%0d|%3b|%3c|%3e)|(\\b(true|false|null)\\b\\s*[=<>])"
    );

    // Padrão para detectar XSS básico
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "(<script|javascript:|onload=|onerror=|onclick=|onmouseover=|eval\\(|alert\\(|document\\.|window\\.|fromCharCode|\\bexpression\\b)"
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

        // Verificar se há tentativas de XSS nos parâmetros
        boolean hasXss = request.getParameterMap().values().stream()
                .flatMap(java.util.Arrays::stream)
                .anyMatch(value -> XSS_PATTERN.matcher(value).matches());

        if (hasSqlInjection || hasXss) {
            logger.warn("Tentativa de ataque detectada de: {} - SQLi: {} - XSS: {}",
                    request.getRemoteAddr(), hasSqlInjection, hasXss);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Entrada inválida detectada");
            return;
        }

        // Continuar com a cadeia de filtros
        filterChain.doFilter(request, response);
    }

    public String sanitizeHtml(String input) {
        if (input == null) return null;
        return htmlSanitizer.sanitize(input);
    }

    public String sanitizeInput(String input) {
        if (input == null) return null;
        // Escape HTML para prevenir XSS
        String sanitized = HtmlUtils.htmlEscape(input);
        // Remover caracteres potencialmente perigosos para SQL
        sanitized = sanitized.replace("'", "''");
        return sanitized;
    }
}