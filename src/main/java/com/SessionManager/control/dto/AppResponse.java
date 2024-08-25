package com.SessionManager.control.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Collection;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AppResponse<T>{
    private int status;
    private String message;

    private final String timeStamp = String.valueOf(LocalDateTime.now());

    private T data;

    private Collection<Object> error;
    public AppResponse(T data) {
        this.data = data;
    }

    public AppResponse(String message, T data) {
        this.message = message;
        this.data = data;
    }

    public AppResponse(int status, Collection<Object> error) {
        this.status = status;
        this.error = error;
    }

    public AppResponse(int status, String message) {
        this.status = status;
        this.message = message;
    }

    public AppResponse(int status, String message, T data) {
        this.status = status;
        this.message = message;
        this.data = data;
    }
}
