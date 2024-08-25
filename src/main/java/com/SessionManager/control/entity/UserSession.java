package com.SessionManager.control.entity;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "user_sessions")
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userEmail;
    private String jwtToken;
    private LocalDateTime createdAt;

    public UserSession() {
        this.createdAt = LocalDateTime.now();
    }
}
