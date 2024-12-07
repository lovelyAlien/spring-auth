package com.ab108.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class SignupRequest {

  @NotBlank(message = "Email is required")
  @Email(message = "Invalid email format")
  private String email;

  @NotBlank(message = "Password is required")
  @Size(min = 6, max = 20, message = "Password must be between 6 and 20 characters")
  private String password;

  @NotBlank(message = "Username is required")
  private String username;

  // Default constructor
  public SignupRequest() {
  }

  // Parameterized constructor
  public SignupRequest(String email, String password, String username) {
    this.email = email;
    this.password = password;
    this.username = username;
  }

  @Override
  public String toString() {
    return "SignupRequest{" +
      "email='" + email + '\'' +
      ", password='******'" +
      ", username='" + username + '\'' +
      '}';
  }
}
