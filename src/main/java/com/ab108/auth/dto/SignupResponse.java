package com.ab108.auth.dto;

import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class SignupResponse {

  private String username;
  private String email;
  private LocalDateTime createdAt;

  // 매개변수 생성자
  public SignupResponse(String username, String email, LocalDateTime createdAt) {
    this.username = username;
    this.email = email;
    this.createdAt = createdAt;
  }

  @Override
  public String toString() {
    return "SignupResponse{" +
      "username='" + username + '\'' +
      ", email='" + email + '\'' +
      ", createdAt=" + createdAt +
      '}';
  }
}

