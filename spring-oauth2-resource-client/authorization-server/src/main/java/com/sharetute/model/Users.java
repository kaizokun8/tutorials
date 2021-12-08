package com.sharetute.model;

import lombok.NoArgsConstructor;
import lombok.Setter;
import javax.persistence.*;
import java.util.Collection;

@Entity
@NoArgsConstructor
@Setter
public class Users {

    @Id
    protected String username;

    protected String password;

    protected Boolean enabled;

    @ManyToMany(fetch = FetchType.LAZY)
    private Collection<Authority> authorities;
}
