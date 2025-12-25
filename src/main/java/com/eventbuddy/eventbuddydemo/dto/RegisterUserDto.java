package com.eventbuddy.eventbuddydemo.dto;

import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.validation.ValidEmail;
import com.eventbuddy.eventbuddydemo.validation.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterUserDto {
    @NotBlank(message = "Email обязателен")
    @ValidEmail
    private String email;

    @NotBlank(message = "Имя обязательно")
    private String name;

    @NotBlank(message = "Пароль обязателен")
    @ValidPassword
    private String password;

    @NotNull(message = "Роль обязательна")
    private User.UserRole role;
}