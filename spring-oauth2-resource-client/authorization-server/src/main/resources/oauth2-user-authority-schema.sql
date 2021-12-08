CREATE TABLE users
(
    username VARCHAR(255),
    password VARCHAR(255),
    enabled  bit(1) default 0,
    primary key (username)
);

CREATE TABLE authority
(
    authority VARCHAR(255),
    primary key (authority)
);

CREATE TABLE authorities
(
    username  VARCHAR(255),
    authority VARCHAR(255),
    primary key (username, authority),
    foreign key (username) REFERENCES users (username),
    foreign key (authority) REFERENCES authority (authority)
);

