package tech.buildrun.springsecurity.config;

import org.springframework.stereotype.Service;

@Service
public class UserValidationService {

    public boolean isValidUsername(String username) {
        if (username == null) {
            return false;
        }

        // Verifica tamanho do username
        if (username.length() < 4 || username.length() > 20) {
            return false;
        }

        // Verifica se contém apenas letras e números
        if (!username.matches("^[a-zA-Z0-9]+$")) {
            return false;
        }

        return true;
    }

    public boolean isValidPassword(String password) {
        if (password == null) {
            return false;
        }

        // Verifica tamanho mínimo da password
        if (password.length() < 8) {
            return false;
        }

        // Verifica se contém pelo menos uma letra maiúscula, uma minúscula e um número
        boolean hasUppercase = false;
        boolean hasLowercase = false;
        boolean hasDigit = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUppercase = true;
            } else if (Character.isLowerCase(c)) {
                hasLowercase = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            }
        }

        return hasUppercase && hasLowercase && hasDigit;
    }
}