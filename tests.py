from simple_key_store import SimpleKeyStore
TEST_KEYSTORE_NAME = "test_keystore"
ks = SimpleKeyStore(TEST_KEYSTORE_NAME)

def test_key_is_added_encrypted():
    my_key_name = "test_key_is_added_encrypted"
    my_key_value = "my password/key"
    ks.delete_records_with_name(my_key_name)
    ks.add_key(name=my_key_name, unencrypted_key=my_key_value)

    cursor = ks.cx.execute("SELECT * from keystore WHERE name=?", (my_key_name,))
    for r in cursor.fetchall():
        print(f"{r=}")
        for field in r:
            assert field != my_key_value, f"Found unencrypted key value in {r}"

    print("key is", ks.get_key(my_key_name))

def test_add_and_retrieve_named_key_without_other_data():
    my_key_name = "test_add_and_retrieve_named_key_without_other_data"
    my_key_value = "1my_password/key_value"
    ks.delete_records_with_name(my_key_name)
    ks.add_key(name=my_key_name, unencrypted_key=my_key_value)

    assert ks.get_key(my_key_name) == my_key_value, f"Expected retrieved key value of {my_key_value} but got {ks.get_key(my_key_name)}"

def test_add_and_retrieve_named_key_with_all_fields():
    my_key_name = "test_add_and_retrieve_named_key_with_all_fields"
    my_key_value = "123abc_" + my_key_name
    ks.delete_records_with_name(my_key_name)

    key_info = {
        "name": my_key_name,
        "key" : my_key_value,
        "batch": "mybatch"
    }
    ks.add_key(name=my_key_name, unencrypted_key=my_key_value)

    assert ks.get_key(my_key_name) == my_key_value, f"Expected retrieved key value of {my_key_value} but got {ks.get_key(my_key_name)}"

if __name__ == "__main__":
    test_key_is_added_encrypted()
    test_add_and_retrieve_named_key_without_other_data()