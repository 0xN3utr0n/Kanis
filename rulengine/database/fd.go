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

// CreateFileDescriptorTable Creates the File Descriptor table.
// Used for real-time per-process file monitoring.
func CreateFileDescriptorTable() error {
	create := `CREATE TABLE
	mem.FileDescriptor (
		"fd" integer NOT NULL,
		"pid" integer NOT NULL,
		"file_id" integer NOT NULL,
		PRIMARY KEY(fd, pid),	
		FOREIGN KEY(file_id) REFERENCES Executable(rowid)	
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

func InsertFileDescriptor(fd, pid int, path string) error {
	insert := `INSERT INTO FileDescriptor(fd, pid, file_id) VALUES 
		(?, ?, (SELECT rowid FROM Executable WHERE path=?));`

	stmt, err := db.Prepare(insert)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(fd, pid, path)
	if err != nil {
		return err
	}

	return nil
}

// GetFileDescriptorPath Retrieves the filepath corresponding to the given file descriptor.
func GetFileDescriptorPath(fd, pid int) (string, error) {
	getpath := `SELECT path FROM Executable JOIN FileDescriptor ON 
			file_id=Executable.rowid WHERE fd=? AND pid=?`

	stmt, err := db.Prepare(getpath)
	if err != nil {
		return "", err
	}

	defer stmt.Close()

	rows, err := stmt.Query(fd, pid)
	if err != nil {
		return "", err
	}

	defer rows.Close()

	var path string
	if rows.Next() {
		rows.Scan(&path)
	}

	return path, nil
}

// DeleteFileDescriptor Deletes the specified descriptor.
func DeleteFileDescriptor(fd, pid int) error {
	delete := "DELETE FROM FileDescriptor WHERE fd=? AND pid=?"

	stmt, err := db.Prepare(delete)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(fd, pid)
	if err != nil {
		return err
	}

	return nil
}

// DeleteAllFileDescriptors Deletes all the descriptors
// own by the process specified by PID.
func DeleteAllFileDescriptors(pid int) error {
	delete := "DELETE FROM FileDescriptor WHERE pid=?"

	stmt, err := db.Prepare(delete)
	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(pid)
	if err != nil {
		return err
	}

	return nil
}

// ExistsFileDescriptor Checks whether the specified descriptor exists.
func ExistsFileDescriptor(fd, pid int) (bool, error) {
	exists := `SELECT 1 FROM FileDescriptor WHERE fd=? AND pid=?`

	stmt, err := db.Prepare(exists)
	if err != nil {
		return false, err
	}

	defer stmt.Close()

	rows, err := stmt.Query(fd, pid)
	if err != nil {
		return false, err
	}

	defer rows.Close()

	if rows.Next() {
		return true, nil
	}

	return false, nil
}
