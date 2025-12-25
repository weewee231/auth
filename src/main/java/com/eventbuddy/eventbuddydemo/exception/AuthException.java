package com.eventbuddy.eventbuddydemo.exception;

import lombok.Getter;

@Getter
public class AuthException extends RuntimeException {
    private String field;
    private String fieldMessage;

    public AuthException(String message) {
        super(message);
    }

    public AuthException(String message, String field) {
        super(message);
        this.field = field;
    }

    public AuthException(String message, String field, String fieldMessage) {
        super(message);
        this.field = field;
        this.fieldMessage = fieldMessage;
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}

