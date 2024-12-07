package com.ab108.auth.repository;

import com.ab108.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
  Boolean existsByEmail(String email);
}
