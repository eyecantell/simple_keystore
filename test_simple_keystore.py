from simple_key_store import SimpleKeyStore

TEST_KEYSTORE_NAME = "keystore_for_tests"
ks = SimpleKeyStore(TEST_KEYSTORE_NAME)


def test_key_is_added_encrypted():
    my_key_name = "test_key_is_added_encrypted"
    my_key_value = "my password/key"
    ks.delete_records_with_name(my_key_name)
    ks.add_key(name=my_key_name, unencrypted_key=my_key_value)

    cursor = ks.cx.execute("SELECT * from keystore WHERE name=?", (my_key_name,))
    for r in cursor.fetchall():
        #print(f"{r=}")
        for field in r:
            assert field != my_key_value, f"Found unencrypted key value in {r}"

    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_add_and_retrieve_named_key_without_other_data():
    my_key_name = "test_add_and_retrieve_named_key_without_other_data"
    my_key_value = "1my_password/key_value"
    ks.delete_records_with_name(my_key_name)
    ks.add_key(name=my_key_name, unencrypted_key=my_key_value)

    assert (
        ks.get_key(my_key_name) == my_key_value
    ), f"Expected retrieved key value of {my_key_value} but got {ks.get_key(my_key_name)}"
    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_add_and_retrieve_named_key_with_all_fields():
    my_key_name = "test_add_and_retrieve_named_key_with_all_fields"
    my_key_value = "123abc_" + my_key_name
    ks.delete_records_with_name(my_key_name)

    key_info = {
        "name": my_key_name,
        "key": my_key_value,
        "active": True,
        "batch": "mybatch",
        "expiration_in_sse": 123456,
        "login": "mylogin",
        "source": "mysource",
    }

    ks.add_key(
        name=key_info["name"],
        unencrypted_key=key_info["key"],
        active=key_info["active"],
        batch=key_info["batch"],
        expiration_in_sse=key_info["expiration_in_sse"],
        login=key_info["login"],
        source=key_info["source"],
    )

    retrieved_key_list = ks.get_matching_key_records(name=my_key_name)
    assert (
        len(retrieved_key_list) == 1
    ), f"Expected one '{my_key_name}' key, but got {len(retrieved_key_list)}"
    retrieved_key_info = retrieved_key_list[0]
    for field in key_info.keys():
        assert retrieved_key_info.get(field), f"No '{field}' in {retrieved_key_info=}"
        assert (
            retrieved_key_info[field] == key_info[field]
        ), f"Expected retrieved key value for {field} of '{key_info[field]}' but got '{retrieved_key_info[field]}'"

    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_build_where_clause_and_values():
    where_clause, values = ks._build_where_clause_and_values(
        name="myname",
        key="my_key_value",
        active=True,
        batch="mybatch",
        expiration_in_sse=123456,
        login="mylogin",
        source="mysource",
    )

    expected_where_clause = ' WHERE name = ? AND expiration_in_sse = ? AND batch = ? AND source = ? AND login = ? AND active = 1'
    expected_values = ['myname', 123456, 'mybatch', 'mysource', 'mylogin']
    assert where_clause == expected_where_clause, f"Expected where_clause to be \n'{expected_where_clause}'\n but got \n'{where_clause}'"
    assert values == expected_values, f"Expected values to be {expected_values} but got {values}"

    # Try again with only a few fields
    where_clause, values = ks._build_where_clause_and_values(
        expiration_in_sse=123456,
        login="mylogin",
        source="mysource",
    )
    expected_where_clause = ' WHERE expiration_in_sse = ? AND source = ? AND login = ?'
    expected_values = [123456, 'mysource', 'mylogin']
    assert where_clause == expected_where_clause, f"Expected where_clause to be \n'{expected_where_clause}'\n but got \n'{where_clause}'"
    assert values == expected_values, f"Expected values to be {expected_values} but got {values}"

    # Try again with only a few fields and one set to None (should be ignored)
    where_clause, values = ks._build_where_clause_and_values(
        expiration_in_sse=123456,
        login="mylogin",
        source="mysource",
        batch = None,
    )
    expected_where_clause = ' WHERE expiration_in_sse = ? AND source = ? AND login = ?'
    expected_values = [123456, 'mysource', 'mylogin']
    assert where_clause == expected_where_clause, f"Expected where_clause to be \n'{expected_where_clause}'\n but got \n'{where_clause}'"
    assert values == expected_values, f"Expected values to be {expected_values} but got {values}"



if __name__ == "__main__":
    test_key_is_added_encrypted()
    test_add_and_retrieve_named_key_without_other_data()
    test_add_and_retrieve_named_key_with_all_fields()
    test_build_where_clause_and_values()
