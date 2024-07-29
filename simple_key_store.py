from cryptography.fernet import Fernet
from tabulate import tabulate
from typing import Any, Dict, List
import os
import sqlite3


class SimpleKeyStore:
    def __init__(self, name: str = "simple_keystore"):
        self.name = name
        self.keystore_key = self.get_simple_keystore_key()
        self.cx = sqlite3.connect(self.name + ".db")
        self.cipher = Fernet(self.keystore_key)
        self.KEYSTORE_TABLE_NAME = "keystore"
        self.create_keystore_table_if_dne()

    def __del__(self):
        self.close_connection()

    def get_simple_keystore_key(self):
        """Get the encryption key from the environment or netrc"""

        # GitHub / Modal / other are expected to have added the key to the environment
        if os.environ.get("SIMPLE_KEYSTORE_KEY"):
            simple_keystore_key = os.environ.get("SIMPLE_KEYSTORE_KEY")
        else:
            import netrc

            try:
                # Attempt to read the key from the .netrc file
                secrets = netrc.netrc().authenticators("SIMPLE_KEYSTORE_KEY")
                if secrets:
                    simple_keystore_key = secrets[2]
                else:
                    raise ValueError("No SIMPLE_KEYSTORE_KEY key found in .netrc file.")
            except (FileNotFoundError, netrc.NetrcParseError, ValueError) as e:
                print(f"Error retrieving SIMPLE_KEYSTORE_KEY key: {e}")
                simple_keystore_key = None

        if not simple_keystore_key:
            raise ValueError("Could not retrieve SIMPLE_KEYSTORE_KEY, was it set in the environment?")

        return simple_keystore_key

    def create_keystore_table_if_dne(self):
        """Create the keystore table if it does not yet exist"""
        self.cx.execute(
            f"CREATE TABLE IF NOT EXISTS {self.KEYSTORE_TABLE_NAME} ( \
                id INTEGER PRIMARY KEY, \
                name TEXT NOT NULL, \
                expiration_in_sse INTEGER, \
                active INTEGER DEFAULT 1, \
                batch TEXT, \
                source TEXT, \
                login TEXT, \
                encrypted_key TEXT UNIQUE\
            )"
        )
        self.cx.commit()

    def keystore_columns(self) -> list[str]:
        """Return the list of columns in the keystore, in the order that they were created"""
        return [
            "id",
            "name",
            "expiration_in_sse",
            "active",
            "batch",
            "source",
            "login",
            "encrypted_key",
        ]

    def generate_key(self):
        return Fernet.generate_key()

    def add_key(
        self,
        name: str,
        unencrypted_key: str,
        active: bool = True,
        expiration_in_sse: int = 0,
        batch: str = None,
        source: str = None,
        login: str = None,
    ) -> int:
        """Add a new key record. Returns the newly created id."""

        self.create_keystore_table_if_dne()
        active_value = 1 if active else 0
        encrypted_key = self.encrypt_key(unencrypted_key)
        cursor = self.cx.execute(
            f"INSERT INTO {self.KEYSTORE_TABLE_NAME} \
                        (name, expiration_in_sse, active, batch, source, login, encrypted_key) VALUES (?,?,?,?,?,?,?)",
            (
                name,
                expiration_in_sse,
                active_value,
                batch,
                source,
                login,
                encrypted_key,
            ),
        )
        self.cx.commit()
        #print("Added key with id", cursor.lastrowid)
        return cursor.lastrowid

    def _record_dicts_from_select_star_results(self, records: list) -> List[Dict]:
        records_list = []
        for r in records:
            record_data = self._get_dict_from_record_tuple(r)
            records_list.append(record_data)
        return records_list

    def _get_dict_from_record_tuple(self, record, include_unencrypted_key=True) -> dict:
        """Presuming a SELECT * was used, this returns a dict of the given record, and includes the unencrypted key."""
        record_data = {}
        i = 0
        for c in self.keystore_columns():
            if c == "active":
                record_data[c] = True if record[i] else False
            else:
                record_data[c] = record[i]
            i = i + 1

        # Include the unencrypted key
        if include_unencrypted_key:
            # Decrypt the key
            record_data["key"] = self.decrypt_key(record_data["encrypted_key"])
        # print(f"{record_data=}")
        return record_data

    def get_key_by_name(self, name: str) -> str:
        """Returns unencrypted key value for the key of the given name. Will raise error if more than one key of this name is found"""

        records = self.get_matching_key_records(name=name)
        if len(records) != 1:
            raise ValueError(f"Got {len(records)} records with {name=}\n{records=}\n")

        return records[0]["key"]

    def get_key_record_by_id(self, id: int) -> Dict:
        """Returns key record for the key with the given id."""

        cursor = self.cx.execute(f"SELECT * FROM {self.KEYSTORE_TABLE_NAME} WHERE id={int(id)}")
        records = self._record_dicts_from_select_star_results(cursor.fetchall())
        if not records:
            return None
        return records[0]
    
    def get_key_record(self, unencrypted_key: str) -> Dict:
        """Returns key record for the given (unencrypted) key."""

        # Because the salt value changes with each encryption, we have to decrypt each key to check against this one
        cursor = self.cx.execute(f"SELECT * FROM {self.KEYSTORE_TABLE_NAME}")
        records = self._record_dicts_from_select_star_results(cursor.fetchall())
        for rec in records: 
            if rec.get('key') == unencrypted_key:
                return rec
        # No record found with the key
        return None
    
    def delete_key_record(self, unencrypted_key: str) -> int:
        """Delete any records with the given key value. Returns number of records deleted"""
        encrypted_key = self.encrypt_key(unencrypted_key)
        cursor = self.cx.execute(f"DELETE FROM {self.KEYSTORE_TABLE_NAME} WHERE encrypted_key=?", (encrypted_key,))
        # print(f"Deleted {cursor.rowcount} records with {encrypted_key=}")
        return cursor.rowcount

    def close_connection(self):
        """Close the db connection (if open)"""
        if self.cx:
            self.cx.close()
            # print("SQLite connection closed.")

    def delete_records_with_name(self, name: str) -> int:
        """Delete any records with the given name. Returns number of records deleted"""
        cursor = self.cx.execute(f"DELETE FROM {self.KEYSTORE_TABLE_NAME} WHERE name=?", (name,))
        # print(f"Deleted {cursor.rowcount} records with {name=}")
        return cursor.rowcount

    def get_matching_key_records(
        self,
        name: str = None,
        active: bool = None,
        expiration_in_sse: int = None,
        batch: str = None,
        source: str = None,
        login: str = None,
    ) -> List[Dict]:
        """Retrieve the keystore records matching the given parameters. Any parameters that are None are ignored."""

        # Construct the base query
        query = f"SELECT * FROM {self.KEYSTORE_TABLE_NAME}"

        cursor = self.run_query_with_where_clause(
            query=query,
            name=name,
            active=active,
            expiration_in_sse=expiration_in_sse,
            batch=batch,
            source=source,
            login=login,
        )

        matching_records = self._record_dicts_from_select_star_results(cursor.fetchall())
        # print(f"{matching_records=}")

        return matching_records

    def delete_matching_key_records(
        self,
        name: str = None,
        active: bool = None,
        expiration_in_sse: int = None,
        batch: str = None,
        source: str = None,
        login: str = None,
    ) -> int:
        """Delete the keystore records matching the given parameters. Any parameters that are None are ignored.
        Returns number of records deleted"""

        # Construct the base query
        query = f"DELETE FROM {self.KEYSTORE_TABLE_NAME}"

        cursor = self.run_query_with_where_clause(
            query=query,
            name=name,
            active=active,
            expiration_in_sse=expiration_in_sse,
            batch=batch,
            source=source,
            login=login,
        )

        return cursor.rowcount

    def run_query_with_where_clause(self, query: str, **kwargs) -> sqlite3.Cursor:
        """Build the WHERE clause for based on the provided key-value pairs and execute the given query. Returns the Cursor."""
        conditions = []
        values: List[Any] = []

        # Create parameterized conditions based on the parameters passed
        for field in self.keystore_columns():
            if field == "active":
                continue
            if field in kwargs and kwargs[field] is not None:
                conditions.append(field + " = ?")
                values.append(kwargs[field])

        if "active" in kwargs and kwargs["active"] is not None:
            conditions.append("active = 1" if kwargs["active"] else "active = 0")

        cursor = None
        if len(conditions):
            # Join all conditions with 'AND'
            where_clause = " WHERE " + " AND ".join(conditions)

            # Execute the query with parameterized values
            # print(f"Executing {query=}")
            cursor = self.cx.execute(query + where_clause, tuple(values))
        else:
            # Just run the query as-is
            print(f"Executing {query=}")
            cursor = self.cx.execute(query)

        return cursor

    def tabulate_records(self, records: List) -> str:
        # Extracting the keys to use as headers
        headers = records[0].keys() if records else []

        # Creating the table using the tabulate module

        table = []  #
        for rec in records:
            row = []
            for header in headers:
                if "key" in header:
                    # Limit keys to the first few characters
                    value = str(rec.get(header, ""))[:18] + "..."
                else:
                    # Limit other fields to 30 chars
                    value = str(rec.get(header, ""))[:30]
                row.append(value)
            table.append(row)

        # Displaying the table with keys as headers
        return tabulate(table, headers=headers)

    def number_of_records(self) -> int:
        """Return the number of key records currently in the db"""
        cursor = self.cx.execute(f"SELECT COUNT(*) FROM {self.KEYSTORE_TABLE_NAME}")
        num_records = int(cursor.fetchone()[0])
        # print(f"Number of records: {num_records}")
        return num_records
    
    def encrypt_key(self, unencrypted_key : str) -> str:
        '''Encrypt the given key'''
        encrypted_key = self.cipher.encrypt(unencrypted_key.encode())
        #print(f"Encrypting\n{unencrypted_key=}\ngives:\n{encrypted_key}")
        return encrypted_key
    
    def decrypt_key(self, encrypted_key : str) -> str:
        '''Decrypt the given key'''
        decrypted_key = self.cipher.decrypt(encrypted_key).decode()
        #print(f"Decrypting\n{encrypted_key=}\ngives:\n{decrypted_key}")
        return decrypted_key
