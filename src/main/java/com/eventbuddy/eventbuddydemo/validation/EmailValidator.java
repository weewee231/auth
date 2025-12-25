package com.eventbuddy.eventbuddydemo.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class EmailValidator implements ConstraintValidator<ValidEmail, String> {

    private static final String EMAIL_PATTERN = 
        "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    
    private static final Pattern pattern = Pattern.compile(EMAIL_PATTERN);
    
    private static final int MIN_LENGTH = 5;
    private static final int MAX_LENGTH = 254;

    @Override
    public boolean isValid(String email, ConstraintValidatorContext context) {
        if (email == null) {
            return true; 
        }

        if (email.trim().isEmpty()) {
            return true; 
        }

        if (email.length() < MIN_LENGTH) {
            return false;
        }

        if (email.length() > MAX_LENGTH) {
            return false;
        }

        if (!email.contains("@")) {
            return false;
        }

        if (email.startsWith("@") || email.endsWith("@")) {
            return false;
        }

        int atIndex = email.indexOf("@");
        String domain = email.substring(atIndex + 1);
        if (!domain.contains(".")) {
            return false;
        }

        String[] parts = domain.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        
        String tld = parts[parts.length - 1];
        if (tld.length() < 2) {
            return false;
        }

        return pattern.matcher(email).matches();
    }
}

