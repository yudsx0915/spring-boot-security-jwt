package com.corey.springbootsecurityjwt.repo;

import com.corey.springbootsecurityjwt.entity.Role;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
