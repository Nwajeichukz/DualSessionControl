package com.SessionManager.control.service;

import com.SessionManager.control.Exception.ApiException;
import com.SessionManager.control.dto.AppResponse;
import com.SessionManager.control.dto.AuthenticationRequest;
import com.SessionManager.control.dto.RegisterRequest;
import com.SessionManager.control.entity.Role;
import com.SessionManager.control.entity.User;
import com.SessionManager.control.repository.RoleRepository;
import com.SessionManager.control.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;

    private final RoleRepository roleRepository;


    private final MyUserDetailsService myUserDetailsService;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;
    private final RedisTemplate<String, String> redisTemplate;


    private final AuthenticationManager authenticationManager;
    private static final String USER_SESSION_KEY_PREFIX = "user:session:";


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

        //check for active sessions
//        List<UserSession> activeSessions = userSessionRepository.findByUserEmail(user.getUsername());
        String redisKey = USER_SESSION_KEY_PREFIX + user.getUsername();
        Set<String> activeSessions = redisTemplate.opsForSet().members(redisKey);

        if (activeSessions != null && activeSessions.size() >= 2) {
            throw new ApiException("User has reached the maximum number of active sessions.");
        }

        var jwtToken = jwtService.generateToken(user);

        String jti = jwtService.getJtiFromToken(jwtToken);

        // Create and save a new session
        redisTemplate.opsForSet().add(redisKey, jti);
        redisTemplate.expire(redisKey, Duration.ofHours(1)); //

        log.info("Storing JWT in Redis with key: {} and token: {}", redisKey, jti);

        return  new AppResponse<>(0,"Successfully logged in", jwtToken);

    }

    public AppResponse<String> logout(String jwtToken) {
        String jti = jwtService.getJtiFromToken(jwtToken);


        String userEmail = jwtService.extractUsername(jwtToken);

        String redisKey = USER_SESSION_KEY_PREFIX + userEmail;

        Long removedCount = redisTemplate.opsForSet().remove(redisKey, jti);

        if (removedCount != null && removedCount > 0) {
            return new AppResponse<>(0, "Successfully logged out.");
        } else {
            return new AppResponse<>(-1, "Invalid token or session already expired.");
        }
    }

}
