package br.com.cya.security.service;

import br.com.cya.security.config.SecurityConfig;
import br.com.cya.security.dto.CreateUserDto;
import br.com.cya.security.dto.LoginUserDto;
import br.com.cya.security.dto.RecoveryJwtTokenDto;
import br.com.cya.security.model.Role;
import br.com.cya.security.model.User;
import br.com.cya.security.repository.UserRepository;
import br.com.cya.security.security.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final UserRepository userRepository;
    private final SecurityConfig securityConfig;

    @Autowired
    public UserService(AuthenticationManager authenticationManager, JwtTokenService jwtTokenService, UserRepository userRepository, SecurityConfig securityConfig) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.userRepository = userRepository;
        this.securityConfig = securityConfig;
    }

    // Autentica usuário e retorna token JWT
    public RecoveryJwtTokenDto authenticateUser(LoginUserDto loginUserDto) {

        // Autenticação com o email e a senha do usuário
        UsernamePasswordAuthenticationToken userTokenAuth = new UsernamePasswordAuthenticationToken(loginUserDto.email(), loginUserDto.password());

        // Autentica o usuário com as credenciais fornecidas
        Authentication authentication = authenticationManager.authenticate(userTokenAuth);

        // UserDetails do usuário autenticado
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        return new RecoveryJwtTokenDto(jwtTokenService.generateToken(userDetails));
    }

    // Criar um usuário
    public void createUser(CreateUserDto createUserDto) {

        User newUser = User.builder()
                .email(createUserDto.email())
                .password(securityConfig.passwordEncoder().encode(createUserDto.password())) // Senha encriptada
                .roles(List.of(Role.builder().name(createUserDto.role()).build())) // Role
                .build();
        userRepository.save(newUser);
    }
}
