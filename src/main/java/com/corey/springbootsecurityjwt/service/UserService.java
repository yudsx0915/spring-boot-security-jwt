package com.corey.springbootsecurityjwt.service;

import java.util.List;

import com.corey.springbootsecurityjwt.entity.Role;
import com.corey.springbootsecurityjwt.entity.User;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
}
