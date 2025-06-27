package com.example.jwtapp.repository;

import org.springframework.stereotype.Repository;
import java.util.Optional;

import com.example.jwtapp.models.Role;
import com.example.jwtapp.models.ERole;
import org.springframework.data.jpa.repository.JpaRepository;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}