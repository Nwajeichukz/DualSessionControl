package com.SessionManager.control.entity;


import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@Entity
@Table(name = "user_section")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, unique = true)
    private Long id;

    private String username;

    private String password;
    private String email;

    @ManyToOne(cascade = CascadeType.PERSIST)
    private Role roles;

}
