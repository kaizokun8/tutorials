CREATE TABLE users
(
    id       bigint auto_increment,
    username VARCHAR(255),
    password VARCHAR(255),
    enabled  bit(1) default 0,
    primary key (id)
);

CREATE TABLE authorities
(
    username  VARCHAR(255),
    authority VARCHAR(255),
    primary key (username, authority),
    foreign key (username) REFERENCES users (username)
);

CREATE TABLE authority
(
    authority VARCHAR(255),
    primary key (authority)
);
