package com.ab108.auth.dto;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class UserLogResponse {
  private Long id;
  private String logType;
  private LocalDateTime timestamp;
  private String message;

  public UserLogResponse(Long id, String logType, LocalDateTime timestamp, String message) {
    this.id = id;
    this.logType = logType;
    this.timestamp = timestamp;
    this.message = message;
  }
}
