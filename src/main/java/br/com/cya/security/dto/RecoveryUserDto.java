package br.com.cya.security.dto;

import br.com.cya.security.model.Role;

import java.util.List;

public record RecoveryUserDto(Long id,
                              String email,
                              List<Role> roles) {
}
