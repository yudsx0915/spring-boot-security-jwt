package com.corey.springbootsecurityjwt.repo;

import com.corey.springbootsecurityjwt.entity.User;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
