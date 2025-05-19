package com.example.Auth_Service.model.dto.request;

import com.example.Auth_Service.model.entity.Role;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequest {
    private String username;
    private String password;
    private Role role;
}
