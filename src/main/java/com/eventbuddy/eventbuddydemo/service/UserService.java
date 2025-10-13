package com.eventbuddy.eventbuddydemo.service;

import com.eventbuddy.eventbuddydemo.model.User;
import com.eventbuddy.eventbuddydemo.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.ArrayList;

@Service
public class UserService {
    public final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public List<User> allUsers() {
        Iterable<User> usersIterable = userRepository.findAll();
        List<User> usersList = new ArrayList<>();
        usersIterable.forEach(usersList::add);
        return usersList;
    }
}