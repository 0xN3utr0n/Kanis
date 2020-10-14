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

// CreateExecutable creates the Executable table.
// It will hold information about all binaries in the system.
// Symbolic-links aren't allowed.
func CreateExecutableTable() error {
	create := `CREATE TABLE IF NOT EXISTS 
	Executable (
		"path" TEXT PRIMARY KEY,
		"dev" integer NOT NULL,		
		"inode" integer NOT NULL,
		"hash" TEXT NOT NULL,
		"danger" integer DEFAULT -1	
	  );`

	stmt, err := db.Prepare(create)
	if err != nil {
		return err
	}

	defer stmt.Close()

	if _, err := stmt.Exec(); err != nil {
		return err
	}

	return nil
}

// InsertExecutable Creates a new entry with information about the given executable.
func InsertExecutable(dev uint64, inode uint64, path string, hash string) error {
	insert := `INSERT or IGNORE INTO Executable(dev, inode, path, hash) VALUES (?, ?, ?, ?)`

	stmt, err := db.Prepare(insert)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(dev, inode, path, hash)
	if err != nil {
		return err
	}

	return nil
}

// UpdateExecutable Updates the corresponding entry for the given executable.
func UpdateExecutable(dev uint64, inode uint64, path string, hash string) error {
	update := `UPDATE Executable SET hash=?, dev=?, inode=?, danger=(case when hash!=? then -1 else danger end) WHERE path=?`

	stmt, err := db.Prepare(update)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(hash, dev, inode, hash, path)
	if err != nil {
		return err
	}

	return nil
}

// UpdateExecutableDanger Updates the corresponding danger field for the given executable.
func UpdateExecutableDanger(path string, danger int) error {
	update := `UPDATE Executable SET danger=? WHERE path=?`

	stmt, err := db.Prepare(update)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(danger, path)
	if err != nil {
		return err
	}

	return nil
}

// ExistsExecutable Checks whether the specified executable exists or not.
func ExistsExecutable(path string) (bool, error) {
	exists := `SELECT 1 FROM Executable WHERE path=?`

	stmt, err := db.Prepare(exists)
	if err != nil {
		return false, err
	}

	defer stmt.Close()

	rows, err := stmt.Query(path)
	if err != nil {
		return false, err
	}

	defer rows.Close()

	if rows.Next() {
		return true, nil
	}

	return false, nil
}

// GetExecutableDanger Gets the danger level for the given executable.
func GetExecutableDanger(path string) (int, error) {
	danger := `SELECT danger FROM Executable WHERE path=?`

	stmt, err := db.Prepare(danger)
	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	rows, err := stmt.Query(path)
	if err != nil {
		return 0, err
	}

	defer rows.Close()

	var d int
	if rows.Next() {
		rows.Scan(&d)
	}

	return d, nil
}

// DeleteExecutable Sets all the fields to 0, almost like unlinking.
// Meant for debugging purposes.
func DeleteExecutable(path string) error {
	delete := "UPDATE Executable SET hash=0, inode=0, dev=0 WHERE path=?"

	stmt, err := db.Prepare(delete)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(path)
	if err != nil {
		return err
	}

	return nil
}
