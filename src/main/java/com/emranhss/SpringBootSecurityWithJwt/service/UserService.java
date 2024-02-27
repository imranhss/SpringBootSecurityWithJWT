package com.emranhss.SpringBootSecurityWithJwt.service;

import com.emranhss.SpringBootSecurityWithJwt.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService  implements UserDetailsService {
    private final IUserRepository userRepository;

    @Override
    // Method signature indicating that this method loads user details based on a username.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Retrieving user details from the UserRepository based on the provided email(username).
        return userRepository.findByEmail(username)

                // If a user is found, return the user details.
                .orElseThrow(() -> new UsernameNotFoundException("no user found with this mail"));

    }
            }
