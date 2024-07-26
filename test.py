from simple_key_store import SimpleKeyStore

ks = SimpleKeyStore("test_keystore")
ks.store_key(name="mykeyname", unencrypted_password="my password")

cursor = ks.cx.execute("SELECT * from keystore")
for r in cursor.fetchall():
    print(r)

print("key is", ks.get_key("mykeyname"))
