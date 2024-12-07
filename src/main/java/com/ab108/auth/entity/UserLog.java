package com.ab108.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "user_logs")
@Getter
@NoArgsConstructor
public class UserLog {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @Column(nullable = false)
  private String logType; // 로그 타입 (e.g., LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT)

  @Column(nullable = false)
  private LocalDateTime timestamp; // 로그 발생 시간

  @Column(nullable = true, length = 500)
  private String message; // 추가적인 메시지 (로그인 실패 이유 등)

  public UserLog(User user, String logType, LocalDateTime timestamp, String message) {
    this.user = user;
    this.logType = logType;
    this.timestamp = timestamp;
    this.message = message;
  }
}
