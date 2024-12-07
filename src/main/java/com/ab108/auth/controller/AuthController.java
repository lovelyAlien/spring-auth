package com.ab108.auth.controller;

import com.ab108.auth.dto.SignupRequest;
import com.ab108.auth.dto.SignupResponse;
import com.ab108.auth.entity.User;
import com.ab108.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  @PostMapping("/users/signup")
  public ResponseEntity<?> signup(@RequestBody SignupRequest request) {

    if (userRepository.existsByEmail(request.getEmail())) {
      return ResponseEntity.badRequest().body("Email already exists");
    }
    String hashedPassword = passwordEncoder.encode(request.getPassword());
    User user = User.builder()
      .email(request.getEmail())
      .password(hashedPassword)
      .username(request.getUsername())
      .build();

    userRepository.save(user);
    return ResponseEntity.ok(new SignupResponse(user.getUsername(), user.getEmail(), user.getCreatedAt()));
  }
}
