package com.ab108.auth.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA를 위한 기본 생성자
@Getter
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, unique = true, length = 100)
  private String email;

  @Column(nullable = false, length = 100)
  private String password;

  @Column(nullable = false, length = 50)
  private String username;

  @Column(nullable = false)
  private LocalDateTime createdAt;

  @Column(nullable = false)
  private boolean active;

  @Enumerated(EnumType.STRING)
  private Authority authority;

  // @Builder를 사용할 수 있도록 매개변수 생성자 추가
  @Builder
  public User(String email, String password, String username, Authority authority) {
    this.email = email;
    this.password = password;
    this.username = username;
    this.authority = authority;
  }

  // 엔티티가 처음 저장될 때 자동으로 값 설정
  @PrePersist
  protected void onCreate() {
    this.createdAt = LocalDateTime.now(); // 현재 시간으로 초기화
    this.active = true; // 기본값을 활성 상태로 설정
  }

  @Override
  public String toString() {
    return "User{" +
      "id=" + id +
      ", email='" + email + '\'' +
      ", username='" + username + '\'' +
      ", createdAt=" + createdAt +
      ", active=" + active +
      '}';
  }
}
