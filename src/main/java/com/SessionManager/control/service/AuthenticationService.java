package com.SessionManager.control.service;

import com.SessionManager.control.Exception.ApiException;
import com.SessionManager.control.dto.AppResponse;
import com.SessionManager.control.dto.AuthenticationRequest;
import com.SessionManager.control.dto.RegisterRequest;
import com.SessionManager.control.entity.Role;
import com.SessionManager.control.entity.User;
import com.SessionManager.control.entity.UserSession;
import com.SessionManager.control.repository.RoleRepository;
import com.SessionManager.control.repository.UserRepository;
import com.SessionManager.control.repository.UserSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final UserSessionRepository userSessionRepository;

    private final MyUserDetailsService myUserDetailsService;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AppResponse<Map<String, Object>> createUser(RegisterRequest request) {
        boolean check = userRepository.existsByUsernameOrEmail(request.getUsername(), request.getEmail());

        if (check) throw new ApiException("User already exists, login to continue");

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        if (!request.getPassword().equals(request.getConfirmPassword()))
            return new AppResponse<>(-1, "passwords do not correspond");

        Role roles = roleRepository.findByName("USER").orElseThrow();
        user.setRoles(roles);

        userRepository.save(user);

        return  new AppResponse<>(0,"User Successfully Saved", Map.of(
                "id", user.getId(),
                "username", user.getUsername(),
                "email", user.getEmail()
        ));

    }

    public AppResponse<String> login(AuthenticationRequest authenticationRequest){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getEmail(), authenticationRequest.getPassword())
        );

        var user = myUserDetailsService.loadUserByUsername(authenticationRequest.getEmail());

        // Retrieve all active sessions for the user
        List<UserSession> activeSessions = userSessionRepository.findByUserEmail(user.getUsername());

        if (activeSessions.size() >= 2) {
            throw new ApiException("User has reached the maximum number of active sessions.");
        }

        var jwtToken = jwtService.generateToken(user);

        // Create and save a new session
        UserSession newSession = new UserSession();
        newSession.setUserEmail(user.getUsername());
        newSession.setJwtToken(jwtToken);
        userSessionRepository.save(newSession);



        return  new AppResponse<>(0,"Successfully logged in", jwtToken);

    }

    public AppResponse<String> logout(String jwtToken) {
        Optional<UserSession> session = userSessionRepository.findByJwtToken(jwtToken);

        if (session.isPresent()) {
            userSessionRepository.deleteById(session.get().getId());
            return new AppResponse<>(0, "Successfully logged out.");
        } else {
            return new AppResponse<>(-1, "Invalid token or session already expired.");
        }
    }

    public void logoutOtherDevices(User user) {
        userSessionRepository.deleteByUserEmail(user.getEmail());
    }
}
