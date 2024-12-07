package com.ab108.auth.config;

import com.ab108.auth.filter.JwtFilter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
  private final JwtFilter jwtFilter;

  @Bean
  protected SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
      .csrf(csrf -> csrf
        .ignoringRequestMatchers("/api/**") // JWT 인증 경로는 CSRF 제외
      )
      .authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN") // 관리자 권한 필요
        .requestMatchers("/users/**").hasAuthority("ROLE_USER")  // 사용자 권한 필요
        .anyRequest().permitAll() // 나머지 요청 허용
      )
      .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
      .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless 세션
      .exceptionHandling(exception -> exception
        .authenticationEntryPoint((request, response, authException) -> {
          response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
          response.getWriter().write("Unauthorized");
        })
      );

    return http.build();
  }


  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
