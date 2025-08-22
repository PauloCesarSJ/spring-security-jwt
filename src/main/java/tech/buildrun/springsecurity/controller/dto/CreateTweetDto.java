package tech.buildrun.springsecurity.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateTweetDto(
        @NotBlank(message = "Conteúdo é obrigatório")
        @Size(max = 280, message = "Tweet não pode exceder 280 caracteres")
        String content
) {}