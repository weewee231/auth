package com.eventbuddy.eventbuddydemo.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class EditProjectDto {
    @NotBlank(message = "Название проекта обязательно")
    private String title;

    private String description;

    @NotNull(message = "Дедлайн обязателен")
    private LocalDateTime deadline;
}

