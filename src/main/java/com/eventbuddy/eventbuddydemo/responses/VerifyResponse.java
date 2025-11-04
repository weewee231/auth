package com.eventbuddy.eventbuddydemo.responses;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerifyResponse {
    private String token;

    public VerifyResponse(String token) {
        this.token = token;
    }
}
