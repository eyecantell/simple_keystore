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
                encrypted_key TEXT \
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
        """Add a new key record. Returns the newly created id"""
        self.create_keystore_table_if_dne()
        active_value = 1 if active else 0
        encrypted_key = self.cipher.encrypt(unencrypted_key.encode())
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
        return cursor.lastrowid

    def record_dicts_from_select_star_results(self, records: list) -> List[Dict]:
        records_list = []
        for r in records:
            record_data = self.get_dict_from_record_tuple(r)
            records_list.append(record_data)
        return records_list

    def get_dict_from_record_tuple(self, record, include_unencrypted_key=True) -> dict:
        """Presuming a SELECT * was used, this returns a dict of the given record."""
        record_data = {}
        i = 0
        for c in self.keystore_columns():
            if c == "active":
                record_data[c] = True if record[i] else False
            else:
                record_data[c] = record[i]
            i = i + 1

        if include_unencrypted_key:
            # Decrypt the key
            record_data["key"] = self.cipher.decrypt(record_data["encrypted_key"]).decode()
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
        records = self.record_dicts_from_select_star_results(cursor.fetchall())
        if not records:
            return None
        return records[0]

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

        matching_records = self.record_dicts_from_select_star_results(cursor.fetchall())
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
        """Build the WHERE clause for a keystore query based on the provided key-value pairs."""
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
            cursor = self.cx.execute(query + where_clause, tuple(values))
        else:
            # Just run the query as-is
            cursor = self.cx.execute(query)

        return cursor

    def tabulate_records(self, records : List) -> str:

        # Extracting the keys to use as headers
        headers = records[0].keys() if records else []

        # Creating the table using the tabulate module
        table = [[str(item.get(header, ""))[:25] for header in headers] for item in records]

        # Displaying the table with keys as headers
        return tabulate(table, headers=headers)
