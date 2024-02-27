package com.emranhss.SpringBootSecurityWithJwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {

    private String token;
    private String message;

//    public AuthenticationResponse(String token, String message) {
//        this.token = token;
//        this.message = message;
//    }
//
//    public String getToken() {
//        return token;
//    }
//
//    public String getMessage() {
//        return message;
//    }
}
