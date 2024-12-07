package com.ab108.auth.controller;

import com.ab108.auth.dto.LoginRequest;
import com.ab108.auth.dto.LoginResponse;
import com.ab108.auth.dto.SignupRequest;
import com.ab108.auth.dto.SignupResponse;
import com.ab108.auth.entity.User;
import com.ab108.auth.repository.UserRepository;
import com.ab108.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {
  private final UserRepository userRepository;
  private final UserService userService;
  private final PasswordEncoder passwordEncoder;

  @PostMapping("/signup")
  public ResponseEntity<?> signup(@RequestBody SignupRequest request) {
    try {
      User user = userService.signup(request);
      return ResponseEntity.ok(new SignupResponse(user.getUsername(), user.getEmail(), user.getCreatedAt()));
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body(e.getMessage());
    }
  }

  @PostMapping("/signin")
  public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
    try {
      String token = userService.login(request.getEmail(), request.getPassword());
      long now = System.currentTimeMillis();
      long expiration = now + 3600 * 1000; // 1 hour validity

      return ResponseEntity.ok(new LoginResponse(token, now / 1000, expiration / 1000));
    } catch (IllegalArgumentException e) {
      return ResponseEntity.badRequest().body("{\"error\": \"" + e.getMessage() + "\"}");
    }
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout(HttpServletRequest request) {
    try {
      userService.logout(request);
      return ResponseEntity.ok("Successfully logged out");
    } catch (Exception e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
    }
  }
}
