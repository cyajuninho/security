package br.com.cya.security.dto;

import br.com.cya.security.security.RoleName;

public record CreateUserDto(String email, String password, RoleName role) {
}
