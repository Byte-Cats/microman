-- Schema for the auth package's MySQL-backed user store.
--
-- This documents the table auth/users.go's FindUserByUsername, CreateUser,
-- and RemoveUser assume exists. It's read (and written) through the raw
-- database/sql connection opened by auth/database.go's ConnectDB/getDB, not
-- through the data package's datastation-based connection.
--
-- Column set matches FindUserByUsername's SELECT exactly:
--   id, username, password, min_username_length, max_username_length,
--   min_password_length, allowed_username_symbols,
--   disallowed_username_start_symbols
--
-- The min/max_username_length, min_password_length, allowed_username_symbols
-- and disallowed_username_start_symbols columns record the UserCredentialRules
-- that were in effect when the account was created (see
-- auth/users.go:defaultUserCredentialRules), so a stored account can later be
-- re-validated against the exact rule shape it was created under rather than
-- whatever rules happen to be hardcoded at call sites.

CREATE TABLE IF NOT EXISTS users (
    id                                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username                           VARCHAR(255) NOT NULL,
    password                           VARCHAR(255) NOT NULL,
    min_username_length                INT NOT NULL DEFAULT 3,
    max_username_length                INT NOT NULL DEFAULT 20,
    min_password_length                INT NOT NULL DEFAULT 8,
    allowed_username_symbols           VARCHAR(255) NOT NULL DEFAULT '_',
    disallowed_username_start_symbols  VARCHAR(255) NOT NULL DEFAULT '_',
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
