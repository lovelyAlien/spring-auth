package com.ab108.auth;

import com.ab108.auth.dto.UserLogResponse;
import com.ab108.auth.entity.UserLog;
import com.ab108.auth.repository.UserLogRepository;
import com.ab108.auth.service.AdminService;
import com.ab108.auth.utils.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

class AdminServiceTest {

  @Mock
  private UserLogRepository userLogRepository;

  @Mock
  private JwtUtil jwtUtil;

  @InjectMocks
  private AdminService adminService;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
  }

  @Test
  void testGetUserLogs_Success() {
    // Given
    Long userId = 1L;
    LocalDateTime startDate = LocalDateTime.now().minusDays(1);
    LocalDateTime endDate = LocalDateTime.now();
    String logType = "LOGIN_SUCCESS";
    Pageable pageable = PageRequest.of(0, 10);

    List<UserLog> logList = Arrays.asList(
      new UserLog(null, logType, startDate.plusHours(1), "Log message 1"),
      new UserLog(null, logType, startDate.plusHours(2), "Log message 2")
    );

    Page<UserLog> logsPage = new PageImpl<>(logList, pageable, logList.size());
    when(userLogRepository.findLogsByFilters(userId, startDate, endDate, logType, pageable)).thenReturn(logsPage);

    // When
    Page<UserLogResponse> result = adminService.getUserLogs(userId, startDate, endDate, logType, pageable);

    // Then
    assertNotNull(result);
    assertEquals(2, result.getTotalElements());
    assertEquals("Log message 1", result.getContent().get(0).getMessage());
    assertEquals("LOGIN_SUCCESS", result.getContent().get(0).getLogType());

    verify(userLogRepository, times(1)).findLogsByFilters(userId, startDate, endDate, logType, pageable);
  }

  @Test
  void testExpireUserTokens_Success() {
    // Given
    Long userId = 1L;

    // When
    adminService.expireUserTokens(userId);

    // Then
    verify(jwtUtil, times(1)).expireUserTokens(userId);
  }
}
