package com.eventbuddy.eventbuddydemo.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PasswordResetDto {
    private String email;
    private String resetCode;
    private String newPassword;
}
