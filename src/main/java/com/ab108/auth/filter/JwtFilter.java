package com.ab108.auth.filter;

import com.ab108.auth.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

  private final JwtUtil jwtUtil;

  public JwtFilter (JwtUtil jwtProvider) {
    this.jwtUtil = jwtProvider;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException {
    try {
      String token = jwtUtil.resolveToken(request);

      if (token != null && jwtUtil.validateToken(token)) {
        Authentication authentication = jwtUtil.getAuthentication(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
      } else {
        SecurityContextHolder.clearContext(); // SecurityContext 초기화
      }

      filterChain.doFilter(request, response);
    } catch (Exception e) {
      SecurityContextHolder.clearContext(); // 예외 발생 시도 초기화
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.getWriter().write("Invalid or expired token");
    }
  }

}
