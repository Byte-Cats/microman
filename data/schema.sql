-- Schema for the `items` example resource used by the /add, /get, /edit and
-- /delete handlers to demonstrate real (as opposed to stubbed) MySQL-backed
-- CRUD via the data package. Written for the MySQL engine this project's
-- datastation-backed Connect() targets.
--
-- Apply it against the database named by DATABASE_NAME (see data/connection.go)
-- before exercising the /add, /get, /edit, /delete routes, e.g.:
--   mysql -h "$DATABASE_HOST" -P "$DATABASE_PORT" -u "$DATABASE_USER" -p "$DATABASE_NAME" < data/schema.sql

CREATE TABLE IF NOT EXISTS items (
    id    INT AUTO_INCREMENT PRIMARY KEY,
    name  VARCHAR(255) NOT NULL,
    value VARCHAR(255) NOT NULL
);
