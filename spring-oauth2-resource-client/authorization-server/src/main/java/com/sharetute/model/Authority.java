package com.sharetute.model;

import lombok.NoArgsConstructor;
import lombok.Setter;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import java.util.Collection;

@Entity
@NoArgsConstructor
@Setter
public class Authority {

    @Id
    protected String authority;

    @ManyToMany(mappedBy = "authorities", fetch = FetchType.LAZY)
    private Collection<Users> users;
}
