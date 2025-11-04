package com.eventbuddy.eventbuddydemo.responses;

import com.eventbuddy.eventbuddydemo.model.User;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthResponse {
    private User user;
    private String accessToken;

    public AuthResponse(User user, String accessToken) {
        this.user = user;
        this.accessToken = accessToken;
    }
}