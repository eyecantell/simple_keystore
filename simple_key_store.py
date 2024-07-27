from cryptography.fernet import Fernet
import sqlite3
import os

class SimpleKeyStore():
    def __init__(self, name : str = "simple_keystore"):
        self.name = name
        self.keystore_key = self.get_simple_keystore_key()
        self.cx = sqlite3.connect(self.name + '.db')
        self.cipher = Fernet(self.keystore_key)
        self.KEYSTORE_TABLE_NAME = "keystore"

    def __del__(self):
        self.close_connection()

    def get_simple_keystore_key(self):
        '''Get the encryption key from the environment or netrc'''
            
        # GitHub / Modal / other are expected to have added the key to the environment
        if os.environ.get('SIMPLE_KEYSTORE_KEY'):
            simple_keystore_key = os.environ.get('SIMPLE_KEYSTORE_KEY')
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
            raise("Could not retrieve SIMPLE_KEYSTORE_KEY, was it set in the environment?")
        
        return simple_keystore_key
    
    def create_keystore_table_if_dne(self):
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
        '''Return the list of columns in the keystore, in the order that they were created'''
        return ["id", "name", "expiration_in_sse", "active", "batch", "source", "login", "encrypted_key"]

    def generate_key(self):
        return Fernet.generate_key()
    
    def add_key(self, name: str, unencrypted_key: str, active: bool=True, expiration_in_sse: int=0, batch: str=None, source: str=None, login: str = None):
        self.create_keystore_table_if_dne()
        active_value = 1 if active else 0
        encrypted_key = self.cipher.encrypt(unencrypted_key.encode())
        self.cx.execute(f"INSERT INTO {self.KEYSTORE_TABLE_NAME} \
                        (name, expiration_in_sse, active, batch, source, login, encrypted_key) VALUES (?,?,?,?,?,?,?)", 
                        (name, expiration_in_sse, active_value, batch, source, login, encrypted_key)
        )
        self.cx.commit()

    def get_dict_from_record_tuple(self, record, include_unencrypted_key = True) -> dict:
        '''Presuming a SELECT * was used, this returns a dict of the given record.'''
        record_data = {}
        i = 0
        for c in self.keystore_columns():
            record_data[c] = record[i]
            i=i+1

        if include_unencrypted_key:
            # Decrypt the key
            record_data["key"] = self.cipher.decrypt(record_data["encrypted_key"]).decode()
        print(f"{record_data=}")
        return record_data

    def get_key(self, name : str) -> str:
        '''Returns key of the given name. Will raise error if more than one key of this name is found'''
        cursor = self.cx.execute(f"SELECT * from {self.KEYSTORE_TABLE_NAME} WHERE name=?", (name,))
        records = cursor.fetchall()
        if len(records) != 1:
            raise (f"Got {len(records)} records with {name=}")
        for r in records:
            record_data = self.get_dict_from_record_tuple(r)
        return record_data["key"]
        
    def close_connection(self):
        '''Close the db connection (if open)'''
        if self.cx:
            self.cx.close()
            print("SQLite connection closed.")

    def delete_records_with_name(self, name: str) -> int:
        '''Delete any records with the given name. Returns number of records deleted'''
        cursor = self.cx.execute(f"DELETE FROM {self.KEYSTORE_TABLE_NAME} WHERE name=?", (name,))
        #print(f"Deleted {cursor.rowcount} records with {name=}")
        return cursor.rowcount
    
    def get_key_records_matching(self, name: str = None, active: bool=None, expiration_in_sse: int=None, batch: str=None, source: str=None, login: str = None):
        '''Retrieve the keystore records matching the given parameters. Any parameters that are None are ignored.'''

        # Construct the base query
        query = f"SELECT * FROM {self.KEYSTORE_TABLE_NAME} WHERE"
        conditions = []
        values = []
        
        # Create conditions based on the parameters passed
        if name is not None:
            conditions.append("name = ?")
            values.append(name)
        if expiration_in_sse is not None:
            conditions.append("expiration_in_sse = ?")
            values.append(expiration_in_sse)
        if batch is not None:
            conditions.append("batch = ?")
            values.append(batch)
        if source is not None:
            conditions.append("source = ?")
            values.append(source)
        if login is not None:
            conditions.append("login = ?")
            values.append(login)
        if active is not None:
            conditions.append("active = 1" if active else "active = 0")
        
        # Join all conditions with 'AND'
        query += " AND ".join(conditions)
        
        # Execute the query with parameterized values
        cursor = self.cx.execute(query, tuple(values))
        matching_records = cursor.fetchall()
        
        return matching_records