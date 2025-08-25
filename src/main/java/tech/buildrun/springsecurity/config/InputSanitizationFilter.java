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

    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i)(\\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|DECLARE|TRUNCATE|CALL|XP_|SP_)\\b|\\b(OR|AND)\\b\\s*[=<>]|--|;|/\\*|\\*/|@@|@|#|\\$|%27|%20|%00|%0a|%0d|%3b|%3c|%3e)|(\\b(true|false|null)\\b\\s*[=<>])"
    );

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

        boolean hasSqlInjection = false;
        boolean hasXss = false;

        // Verificar apenas parâmetros de consulta para performance
        for (String paramName : request.getParameterMap().keySet()) {
            String[] paramValues = request.getParameterValues(paramName);
            for (String value : paramValues) {
                if (SQL_INJECTION_PATTERN.matcher(value).find()) {
                    hasSqlInjection = true;
                    break;
                }
                if (XSS_PATTERN.matcher(value).find()) {
                    hasXss = true;
                    break;
                }
            }
            if (hasSqlInjection || hasXss) break;
        }

        if (hasSqlInjection || hasXss) {
            logger.warn("Tentativa de ataque detectada de: {} - SQLi: {} - XSS: {}",
                    request.getRemoteAddr(), hasSqlInjection, hasXss);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Entrada inválida");
            return;
        }

        filterChain.doFilter(request, response);
    }

    public String sanitizeHtml(String input) {
        if (input == null) return null;
        return htmlSanitizer.sanitize(input);
    }

    public String sanitizeInput(String input) {
        if (input == null) return null;
        return HtmlUtils.htmlEscape(input).replace("'", "''");
    }
}