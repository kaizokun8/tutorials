use oauth2;

INSERT INTO users (username, password, enabled)
VALUES ('john', '$2a$10$hn37faXn3NwbNecgVcmWiuD0q4cn7C.uCpGZfuzHqRV8lB7W7zz3y', 1);

INSERT INTO authorities (username, authority)
VALUES ('john', 'ROLE_USER');

INSERT INTO authority (authority)
VALUES ('ROLE_USER'),
       ('ROLE_ADMIN'),
       ('ROLE_SUPER_ADMIN'),
       ('ROLE_APPLICATION');

