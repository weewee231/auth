package com.eventbuddy.eventbuddydemo.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = EmailValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidEmail {
    String message() default "Email должен содержать @, иметь корректный формат";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}

