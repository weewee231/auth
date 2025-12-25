package com.eventbuddy.eventbuddydemo.dto;

import com.eventbuddy.eventbuddydemo.model.User;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
public class UserDto {
    private UUID id;
    private String email;
    private String name;
    private User.UserRole role;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public UserDto(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.name = user.getNameField();
        this.role = user.getRole();
        this.createdAt = user.getCreatedAt();
        this.updatedAt = user.getUpdatedAt();
    }
}

