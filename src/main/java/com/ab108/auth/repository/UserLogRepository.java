package com.ab108.auth.repository;

import com.ab108.auth.entity.UserLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface UserLogRepository extends JpaRepository<UserLog, Long> {

  @Query("SELECT l FROM UserLog l WHERE l.user.id = :userId " +
    "AND (:startDate IS NULL OR l.timestamp >= :startDate) " +
    "AND (:endDate IS NULL OR l.timestamp <= :endDate) " +
    "AND (:logType IS NULL OR l.logType = :logType)")
  Page<UserLog> findLogsByFilters(@Param("userId") Long userId,
                                  @Param("startDate") LocalDateTime startDate,
                                  @Param("endDate") LocalDateTime endDate,
                                  @Param("logType") String logType,
                                  Pageable pageable);
}
