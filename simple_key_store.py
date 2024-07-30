from cryptography.fernet import Fernet
from datetime import datetime
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
        # Keep this in sync with create_keystore_table_if_dne()
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
        # print("Added key with id", cursor.lastrowid)
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

        # Change the expiration_in_sse to a date
        record_data["expiration_date"] = None
        if record_data.get("expiration_in_sse"):
            record_data["expiration_date"] = datetime.fromtimestamp(int(record_data.get("expiration_in_sse")))
        today = datetime.today()

        # Add whether the record is expired
        record_data["expired"] = False if record_data.get("expiration_date") is None else (record_data["expiration_date"] < today)

        # Add whether the record is usable (active and not expired)
        record_data["usable"] = record_data["active"] and not record_data["expired"]

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
            if rec.get("key") == unencrypted_key:
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
        sort_order: List = None,
    ) -> List[Dict]:
        """Retrieve the keystore records matching the given parameters. Any parameters that are None are ignored.
        Sort order can be specified using any/all of the columns including calculated ones (expired, usable, expiration_date)"""

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

        if sort_order:
            matching_records.sort(key=lambda x: tuple(x.get(field) for field in sort_order))

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
            # print(f"Executing {query=}")
            cursor = self.cx.execute(query)

        return cursor

    def tabulate_records(self, records: List[Dict], headers: List = None, sort_order: List = None) -> str:
        """Return a string of tabulated records. If headers is blank will use all keys. If given will sort by keys listed in sort_order."""
        # Extracting the keys to use as headers

        if not records:
            return "No records to tabulate"

        # If no headers were passed, use all of the keys
        if not headers:
            headers = records[0].keys()

        # If sort_order was passed, sort the records by the given keys (in order given)
        if sort_order:
            records.sort(key=lambda x: tuple(x.get(field) for field in sort_order))

        # Creating the table using the tabulate module

        table = []  #
        for rec in records:
            row = []
            for header in headers:
                if "key" in header:
                    # Limit keys to the first and last few characters
                    key_value = str(rec.get(header))
                    if key_value:
                        value = key_value[:8] + "..." + key_value[-8:]
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

    def encrypt_key(self, unencrypted_key: str) -> str:
        """Encrypt the given key"""
        if not unencrypted_key:
            return None
        encrypted_key = self.cipher.encrypt(unencrypted_key.encode())
        # print(f"Encrypting\n{unencrypted_key=}\ngives:\n{encrypted_key}")
        return encrypted_key

    def decrypt_key(self, encrypted_key: str) -> str:
        """Decrypt the given key"""
        if not encrypted_key:
            return None
        decrypted_key = self.cipher.decrypt(encrypted_key).decode()
        # print(f"Decrypting\n{encrypted_key=}\ngives:\n{decrypted_key}")
        return decrypted_key

    def records_for_usability_report(
        self,
        key_name: str = None,
        print_records: bool = False,
        sort_order: List = ["name", "source", "login", "batch", "active", "expiration_date"],
    ) -> List[Dict]:
        """Get list of sorted key records with the given name. Gets ALL if no name given.
        Will print a tabulated list of the records if print_records is True"""
        key_records = self.get_matching_key_records(name=key_name, sort_order = sort_order)

        if print_records:
            print(
                self.tabulate_records(
                    key_records, headers=sort_order + ["expired", "usable", "key"], sort_order=sort_order
                )
            )
        return key_records

    def usability_counts_report(
        self, key_name: str = None, print_records: bool = False, print_counts=False
    ) -> List[Dict]:
        usability_records = self.records_for_usability_report(key_name, print_records)

        # Count the number of usable records for each set, where avset is combo of name, source, login, batch
        usable_count_by_qualified_name = {}
        unusable_count_by_qualified_name = {}
        usable_count = 0
        unusable_count = 0
        qual_fields = ["name", "source", "login", "batch"]
        delim = "+|+"
        for record in usability_records:
            # print(f"{record=}")

            qualified_name = delim.join(str(record[field]) for field in qual_fields)
            # print(f"{qualified_name=}")
            if qualified_name not in usable_count_by_qualified_name:
                usable_count_by_qualified_name[qualified_name] = 0
            if qualified_name not in unusable_count_by_qualified_name:
                unusable_count_by_qualified_name[qualified_name] = 0

            if record["usable"]:
                usable_count_by_qualified_name[qualified_name] += 1
                usable_count += 1
            else:
                unusable_count_by_qualified_name[qualified_name] += 1
                unusable_count += 1

        # Create records with the counts that we can tabulate
        records_for_count_display = []
        for qualified_name in usable_count_by_qualified_name.keys():
            # print(f"{qualified_name}: usable={usable_count_by_qualified_name[qualified_name]}, unusable={unusable_count_by_qualified_name[qualified_name]}")
            field_values = str(qualified_name).split(delim)
            count_record = {}
            i = 0
            for field in qual_fields:
                count_record[field] = field_values[i]
                i += 1
            count_record["usable"] = usable_count_by_qualified_name[qualified_name]
            count_record["unusable"] = unusable_count_by_qualified_name[qualified_name]
            records_for_count_display.append(count_record)

        if print_counts:
            print(
                f"Usability counts ({len(usability_records)} records total, {usable_count} usable, {unusable_count} not)"
            )
            print(self.tabulate_records(records_for_count_display))

        return records_for_count_display

    def update_key(
        self,
        id_to_update: int,
        name: str = None,
        active: bool = None,
        expiration_in_sse: int = None,
        batch: str = None,
        source: str = None,
        login: str = None,
    ):
        """Update the key record with the given values. Raises error if update fails."""
        params = {}
        set_clause = []

        if type(id_to_update).__name__ != "int":
            raise ValueError(f"Expected id_to_update to be an integer, but got {type(id_to_update)}={id_to_update}")

        if name is not None:
            params["name"] = name
            set_clause.append("name = :name")

        if active is not None:
            params["active"] = active
            set_clause.append("active = :active")

        if expiration_in_sse is not None:
            params["expiration_in_sse"] = expiration_in_sse
            set_clause.append("expiration_in_sse = :expiration_in_sse")

        if batch is not None:
            params["batch"] = batch
            set_clause.append("batch = :batch")

        if source is not None:
            params["source"] = source
            set_clause.append("source = :source")

        if login is not None:
            params["login"] = login
            set_clause.append("login = :login")

        if not set_clause:
            # Noting was given to set
            return

        sql = f"UPDATE {self.KEYSTORE_TABLE_NAME} SET {', '.join(set_clause)} WHERE id = :id"
        cursor = self.cx.execute(sql, {"id": int(id_to_update), **params})

        if cursor.rowcount != 1:
            raise RuntimeError(f"Update failed with {sql=}, {params=}")

    def mark_key_inactive(self, unencrypted_key: str) -> int:
        """Mark the given key inactive."""
        record = self.get_key_record(unencrypted_key)
        number_of_records_updated = self.update_key(record["id"], active=False)

        return number_of_records_updated

    def get_next_active_key(
        self,
        name: str = None,
        batch: str = None,
        source: str = None,
        login: str = None,
    ):
        """Return the next key to use that matches the given fields. Will look for:
        1. Soonest expiring
        2. Smallest batch of active keys"""
        matching_records = self.get_matching_key_records(name=name, active=True, )
