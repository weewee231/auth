package com.eventbuddy.eventbuddydemo.dto;

import com.eventbuddy.eventbuddydemo.model.User;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterUserDto {
    private String email;
    private String password;
    private User.UserRole role;
}