package com.eventbuddy.eventbuddydemo.dto;

import com.eventbuddy.eventbuddydemo.validation.ValidEmail;
import com.eventbuddy.eventbuddydemo.validation.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordResetDto {
    @NotBlank(message = "Email обязателен")
    @ValidEmail
    private String email;

    @NotBlank(message = "Код обязателен")
    private String code;

    @NotBlank(message = "Новый пароль обязателен")
    @ValidPassword
    private String newPassword;
}