// Copyright (C) 2020-2021,  0xN3utr0n

// Kanis is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Kanis is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Kanis. If not, see <http://www.gnu.org/licenses/>.

package database

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3" // Sql driver
)

var db *sql.DB

const dbpath = "/var/kanis/kanis.db"

// NewDb Creates and opens the Kanis.db database.
func NewDb() error {
	// Check if it exists, otherwise create the database file.
	fd, err := os.OpenFile(dbpath, os.O_RDONLY|os.O_CREATE, 0700)
	if err != nil {
		return err
	}

	fd.Close()

	db, err = sql.Open("sqlite3", dbpath)
	if err != nil {
		return err
	}

	if _, err := db.Exec(`ATTACH '' AS 'mem'`); err != nil {
		return err
	}

	// Added due to connection error
	// ref: https://github.com/mattn/go-sqlite3/issues/204
	db.SetMaxOpenConns(1)

	return nil
}

// TableExists Checks whether the specified table exists or not.
func TableExists(name string) bool {
	exists := `SELECT name FROM sqlite_master WHERE 
				type='table' AND name=?`

	stmt, err := db.Prepare(exists)
	if err != nil {
		return false
	}

	defer stmt.Close()

	rows, err := stmt.Query(name)
	if err != nil {
		return false
	}

	defer rows.Close()

	if rows.Next() {
		return true
	}

	return false
}
