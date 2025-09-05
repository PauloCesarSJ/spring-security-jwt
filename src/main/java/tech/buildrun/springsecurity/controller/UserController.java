package tech.buildrun.springsecurity.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import tech.buildrun.springsecurity.config.InputSanitizationFilter;
import tech.buildrun.springsecurity.config.UserValidationService;
import tech.buildrun.springsecurity.controller.dto.CreateUserDto;
import tech.buildrun.springsecurity.entities.Role;
import tech.buildrun.springsecurity.entities.User;
import tech.buildrun.springsecurity.repository.RoleRepository;
import tech.buildrun.springsecurity.repository.UserRepository;

import java.util.List;
import java.util.Set;
@RestController
public class UserController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final InputSanitizationFilter inputSanitizationFilter;
    private final UserValidationService userValidationService;

    public UserController(UserRepository userRepository,
                          RoleRepository roleRepository,
                          BCryptPasswordEncoder passwordEncoder,
                          InputSanitizationFilter inputSanitizationFilter,
                          UserValidationService userValidationService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.inputSanitizationFilter = inputSanitizationFilter;
        this.userValidationService = userValidationService;
    }

    @Transactional
    @PostMapping("/users")
    public ResponseEntity<Void> newUser(@RequestBody CreateUserDto dto) {
        String sanitizedUsername = inputSanitizationFilter.sanitizeInput(dto.username());

        // Valida o username usando o serviço dedicado
        if (!userValidationService.isValidUsername(sanitizedUsername)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Username deve ter entre 4 e 20 caracteres e conter apenas letras e números"
            );
        }

        // Valida a password usando o serviço dedicado
        if (!userValidationService.isValidPassword(dto.password())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password deve ter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma minúscula e um número"
            );
        }

        var basicRole = roleRepository.findByName(Role.Values.BASIC.name());

        if (userRepository.findByUsername(sanitizedUsername).isPresent()) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Usuário já cadastrado");
        }

        var user = new User();
        user.setUsername(sanitizedUsername);
        user.setPassword(passwordEncoder.encode(dto.password()));
        user.setRoles(Set.of(basicRole));

        userRepository.save(user);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<List<User>> listUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }
}