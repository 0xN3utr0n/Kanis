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

// CreateNameSpacesTable Creates the File Descriptor table.
func CreateNameSpacesTable() error {
	create := `CREATE TABLE
	mem.Namespaces (
		"flag" integer,
		"data" TEXT
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

// GetNamespace
func GetNamespace(id int64) (flag uint64, data string, err error) {

	getpath := `SELECT flag, data FROM Namespaces WHERE rowid=?`

	stmt, err := db.Prepare(getpath)
	if err != nil {
		return 0, "", err
	}

	defer stmt.Close()

	rows, err := stmt.Query(id)
	if err != nil {
		return 0, "", err
	}

	defer rows.Close()

	if rows.Next() {
		rows.Scan(&flag, &data)
	}

	return flag, data, nil
}

// NewNamespace
func NewNamespace(flag uint64, data string) (int64, error) {
	insert := `INSERT INTO Namespaces(flag, data) VALUES (?,?)`

	stmt, err := db.Prepare(insert)
	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	result, err := stmt.Exec(flag, data)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, nil
	}

	return id, nil
}

func UpdateNamespace(id int64, data string) error {
	insert := `UPDATE Namespaces SET data=? WHERE rowid=?`

	stmt, err := db.Prepare(insert)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(data, id)
	if err != nil {
		return err
	}

	return nil
}
