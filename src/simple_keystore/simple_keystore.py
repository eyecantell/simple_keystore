from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from tabulate import tabulate
from typing import Any, Dict, List
import os
import sqlite3


class SimpleKeyStore:
    def __init__(self, name: str = "simple_keystore.db"):
        self.name = name
        self.keystore_key = self.get_simple_keystore_key()
        self.cx = sqlite3.connect(self.name)
        self.cipher = Fernet(self.keystore_key)
        self.KEYSTORE_TABLE_NAME = "keystore"
        self.create_keystore_table_if_dne()

        self.set_defining_fields = ["name", "source", "login", "batch"]

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
                encrypted_key TEXT UNIQUE, \
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP \
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
        """Presuming a SELECT * was used, this returns a dict of the given record, and includes the unencrypted key.
        Also includes calculated fields: expiration_date, expired, and usable (active and not expired)."""
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
        record_data["expired"] = (
            False if record_data.get("expiration_date") is None else (record_data["expiration_date"] < today)
        )

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
        key_record = self.get_key_record(unencrypted_key)
        cursor = self.cx.execute(f"DELETE FROM {self.KEYSTORE_TABLE_NAME} WHERE id=?", (key_record["id"],))
        # print(f"Deleted {cursor.rowcount} records with {encrypted_key=}")
        self.cx.commit()
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

    def tabulate_records(
        self,
        records: List[Dict],
        headers: List = None,
        sort_order: List = None,
        show_full_key: bool = False,
        show_index: bool = True,
    ) -> str:
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
                    if header == "key" and show_full_key:
                        value = key_value
                    elif len(value) > 20:
                        value = key_value[:8] + "..." + key_value[-8:]
                    else:
                        value = key_value
                else:
                    # Limit other fields to 30 chars
                    value = str(rec.get(header, ""))[:30]
                row.append(value)
            table.append(row)

        # Displaying the table with keys as headers
        return tabulate(table, headers=headers, showindex=show_index)

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
        key_records = self.get_matching_key_records(name=key_name, sort_order=sort_order)

        if print_records:
            print(
                self.tabulate_records(
                    key_records,
                    headers=sort_order + ["expired", "usable", "key"],
                    sort_order=sort_order,
                    show_full_key=True,
                    show_index=True,
                )
            )
        return key_records

    def usability_counts_report(
        self, key_name: str = None, print_records: bool = False, print_counts=False
    ) -> List[Dict]:
        usability_records = self.records_for_usability_report(key_name, print_records)

        # Count the number of usable records for each set, where a set is combo of name, source, login, batch
        set_records = self.get_sets_of_records_with_counts(usability_records)
        usable_count = sum(1 for record in set_records if record.get("usable"))

        if print_counts:
            print(f"Usability counts ({len(usability_records)} records total, {usable_count} usable)")
            print(self.tabulate_records(set_records, show_index=True))

        return set_records

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

        sql = f"UPDATE {self.KEYSTORE_TABLE_NAME} SET {', '.join(set_clause)}, updated_at = CURRENT_TIMESTAMP WHERE id = :id"
        cursor = self.cx.execute(sql, {"id": int(id_to_update), **params})

        if cursor.rowcount != 1:
            raise RuntimeError(f"Update failed with {sql=}, {params=}")
        self.cx.commit()

    def mark_key_inactive(self, unencrypted_key: str) -> int:
        """Mark the given key inactive."""
        record = self.get_key_record(unencrypted_key)
        number_of_records_updated = self.update_key(record["id"], active=False)

        return number_of_records_updated

    def mark_key_active(self, unencrypted_key: str) -> int:
        """Mark the given key active."""
        record = self.get_key_record(unencrypted_key)
        number_of_records_updated = self.update_key(record["id"], active=True)

        return number_of_records_updated

    def get_sets_of_records_with_counts(self, records: List[Dict]):
        """Return a list of the record sets with their counts. Each set of records share name, source, login and batch."""

        count_fields = ["total", "active", "expired", "usable"]

        count_by_set_name = {}
        min_upcoming_expiration_by_set_name = {}
        delim = "+|+"
        for record in records:
            set_name = delim.join(str(record.get(field)) for field in self.set_defining_fields)
            if set_name not in count_by_set_name:
                count_by_set_name[set_name] = {}
                for cf in count_fields:
                    count_by_set_name[set_name][cf] = 0

            count_by_set_name[set_name]["total"] += 1
            for cf in count_fields:
                if cf == "total":
                    # Already counted total above (and there likely is no record value for it)
                    continue
                # Count each of active, expired, usable
                count_by_set_name[set_name][cf] += 1 if record[cf] else 0

            # Keep track of the minimum upcoming (non-expired) expiration date for this set
            if set_name not in min_upcoming_expiration_by_set_name:
                min_upcoming_expiration_by_set_name[set_name] = None
            if record["expired"]:
                continue
            if (
                min_upcoming_expiration_by_set_name[set_name] is None
                or record["expiration_date"] < min_upcoming_expiration_by_set_name[set_name]
            ):
                min_upcoming_expiration_by_set_name[set_name] = record["expiration_date"]

        # print(f"{count_by_set_name=}")

        # Build a "set record" that will have each of the set defining fields and the counts
        set_records_list = []
        for set_name in count_by_set_name.keys():
            # Prepare a new set record
            set_record = {}
            # Get the set defining field values from the set_name
            field_values = str(set_name).split(delim)
            i = 0
            for field in self.set_defining_fields:
                # print(f"{type(field_values[i])}, {field_values[i]=}")
                set_record[field] = None if field_values[i] == "None" else field_values[i]
                i += 1

            # Add the counts
            for cf in count_fields:
                set_record[cf] = count_by_set_name[set_name][cf]

            # Add the min upcoming expiration date
            set_record["upcoming_expiration"] = min_upcoming_expiration_by_set_name[set_name]

            # Save our set record
            set_records_list.append(set_record)

        # print(f"{set_records_list=}")
        return set_records_list

    def record_is_in_set(self, record: Dict, record_set: Dict) -> bool:
        """Returns true if record and set match on all the set defining fields"""
        # print("record_is_in_set checking:")

        for field in self.set_defining_fields:
            # print(f"  checking {field}: {type(record.get(field))} {record.get(field)}, {type(record_set.get(field))} {record_set.get(field)}")

            if record.get(field) != record_set.get(field):
                # print(f"    {record[field]} != {record_set[field]}")
                return False
            # print(f"    {record[field]} == {record_set[field]}")
        return True

    def get_set_for_record(self, record: Dict, record_set_list: List[Dict]) -> Dict:
        """Returns the record set (Dict) of the set that matches the given record."""
        for record_set in record_set_list:
            if self.record_is_in_set(record, record_set):
                # print("Found record set for record")
                return record_set
        # print("Did not find record set for record")
        return None

    def get_next_usable_key(
        self,
        name: str = None,
        batch: str = None,
        source: str = None,
        login: str = None,
    ):
        """Return the next usable key that matches the given fields. Will look for:
        1. Soonest expiring (by 12 hours)
        2. Smallest set of usable keys, where set is combo of name, source, login, batch"""
        matching_records = self.get_matching_key_records(
            name=name,
            active=True,
            batch=batch,
            source=source,
            login=login,
        )

        # print(f"Got {len(matching_records)} matching records")
        # Find the soonest upcoming expiration date
        soonest_expiration = None
        for record in matching_records:
            if not record["usable"]:
                continue
            if soonest_expiration is None or record["expiration_date"] < soonest_expiration:
                soonest_expiration = record["expiration_date"]
        # print(f"{soonest_expiration=}")

        # Get the records that are soonest to expire (within 12 hours)
        soon_to_expire_records = []
        twelve_hours_in_seconds = 12 * 3600
        for record in matching_records:
            if record["expiration_date"] is None:
                continue
            time_diff = record["expiration_date"] - soonest_expiration
            if time_diff.total_seconds() < twelve_hours_in_seconds:
                soon_to_expire_records.append(record)

        # print(self.tabulate_records(soon_to_expire_records, headers=['id','name','expiration_date','key'] + self.set_defining_fields))
        # If only one record has soonest expiration just return it
        if len(soon_to_expire_records) == 1:
            # print("Only one record, returning")
            return soon_to_expire_records[0]["key"]

        if not soon_to_expire_records:
            # None of the records have an expiration date
            soon_to_expire_records = matching_records

        # Break the "tie" by choosing the record with the least number of usable records in its set
        record_set_list = self.get_sets_of_records_with_counts(matching_records)
        # print(f"{record_set_list=}")
        record_with_min_usable_set = None
        min_usable = None
        for record in soon_to_expire_records:
            record_set = self.get_set_for_record(record, record_set_list)
            # print(f"{record_set=}")
            if min_usable is None or record_set.get("usable") < min_usable:
                min_usable = record_set.get("usable")
                record_with_min_usable_set = record

        # print(f"{record_with_min_usable_set=}")
        if record_with_min_usable_set:
            return record_with_min_usable_set.get("key")
        return None
