package com.ab108.auth.dto;

import lombok.Getter;

@Getter
public class LoginResponse {
  private String token;
  private long iat;
  private long exp;

  public LoginResponse(String token, long iat, long exp) {
    this.token = token;
    this.iat = iat;
    this.exp = exp;
  }
}
