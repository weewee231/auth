package com.eventbuddy.eventbuddydemo.dto;

import com.eventbuddy.eventbuddydemo.validation.ValidEmail;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginUserDto {
    @NotBlank(message = "Email обязателен")
    @ValidEmail
    private String email;

    @NotBlank(message = "Пароль обязателен")
    private String password;
}