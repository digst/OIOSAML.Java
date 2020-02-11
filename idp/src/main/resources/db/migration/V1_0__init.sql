CREATE TABLE users (
    id          BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,

    username    VARCHAR(256) UNIQUE NOT NULL,
    password    VARCHAR(256) NOT NULL,
    attribute_profile    VARCHAR(256),
    level_of_assurance    VARCHAR(256)
);