package com.SessionManager.control.repository;

import com.SessionManager.control.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    List<UserSession> findByUserEmail(String email);

    void deleteByUserEmail(String email);

    Optional<UserSession> findByJti(String jti);
}
