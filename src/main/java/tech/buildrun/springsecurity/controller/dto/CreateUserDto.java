package tech.buildrun.springsecurity.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateUserDto(
        @NotBlank(message = "Username é obrigatório")
        String username,

        @NotBlank(message = "Password é obrigatório")
        @Size(min = 6, message = "Password deve ter pelo menos 6 caracteres")
        String password
) {}