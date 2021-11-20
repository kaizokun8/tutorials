drop schema if exists oauth2;
create schema oauth2;
use oauth2;

drop table if exists users;
create table users
(
    id       bigint auto_increment,
    username VARCHAR(255),
    password VARCHAR(255),
    enabled  bit(1) default 0,
    primary key (id)
);

drop table if exists authorities;
create table authorities
(
    username VARCHAR(255),
    authority VARCHAR(255),
    primary key (username, authority),
    foreign key (username) REFERENCES users(username)
);
