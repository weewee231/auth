package com.eventbuddy.eventbuddydemo.dto;

import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.validation.ValidEmail;
import com.eventbuddy.eventbuddydemo.validation.ValidPassword;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateUserDto {
    @ValidEmail
    private String email;

    private String name;

    @ValidPassword
    private String password;

    private User.UserRole role;
}

