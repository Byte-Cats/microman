package data

// Database connection logic for the application

import (
	"database/sql"

	datastation "github.com/byte-cats/datastation/pkg"
)

// Connect opens a database connection via datastation
// (https://github.com/byte-cats/datastation), the library the project uses
// to let a deployment choose and configure its database quickly.
//
// Configuration is read from the DATABASE_TYPE, DATABASE_HOST, DATABASE_PORT,
// DATABASE_NAME, DATABASE_USER and DATABASE_PASSWORD environment variables,
// falling back to datastation's MySQL defaults for anything left unset.
//
// datastation's connection helper (NewDBConnection) is MySQL-specific today,
// so this only wires up MySQL; datastation also ships Postgres/Mongo/Redis
// helpers (pkg.SetupPostgres, pkg.ConnectMongoDB, pkg.NewRedisClient) that a
// future DATABASE_TYPE switch could dispatch to once this project actually
// needs one of those engines.
func Connect() (*sql.DB, error) {
	cfg := datastation.DefaultMySqlConf()
	cfg.DatabaseConfig = datastation.GetDatabase(cfg.DatabaseConfig)
	// NewDBConnection builds its DSN from cfg.DBName rather than
	// cfg.DatabaseConfig.Name, so keep the two in sync or a DATABASE_NAME
	// override would silently have no effect.
	cfg.DBName = cfg.DatabaseConfig.Name

	return datastation.NewDBConnection(cfg)
}

// Close closes a database connection opened via Connect.
func Close(db *sql.DB) {
	datastation.CloseMySQL(db)
}
