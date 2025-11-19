package com.sk.tradeverse.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.sk.tradeverse.domain.USER_ROLE;
import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    private String fullname;
    private String email;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    @Embedded
    private TwoFactorAuth twoFactorAuth=new TwoFactorAuth();

    private USER_ROLE role= USER_ROLE.ROLE_USER;
}
