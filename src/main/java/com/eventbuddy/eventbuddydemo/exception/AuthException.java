package com.eventbuddy.eventbuddydemo.exception;

public class AuthException extends RuntimeException {
    private String field;

    public AuthException(String message) {
        super(message);
    }

    public AuthException(String message, String field) {
        super(message);
        this.field = field;
    }

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getField() {
        return field;
    }
}

