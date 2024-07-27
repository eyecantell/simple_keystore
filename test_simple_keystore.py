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
        # print(f"{r=}")
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
        ks.get_key_by_name(my_key_name) == my_key_value
    ), f"Expected retrieved key value of {my_key_value} but got {ks.get_key_by_name(my_key_name)}"
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
    assert len(retrieved_key_list) == 1, f"Expected one '{my_key_name}' key, but got {len(retrieved_key_list)}"
    retrieved_key_info = retrieved_key_list[0]
    for field in key_info.keys():
        assert retrieved_key_info.get(field), f"No '{field}' in {retrieved_key_info=}"
        assert (
            retrieved_key_info[field] == key_info[field]
        ), f"Expected retrieved key value for {field} of '{key_info[field]}' but got '{retrieved_key_info[field]}'"

    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_delete_matching_key_records():
    my_key_name = "test_delete_matching_key_records"
    my_key_value = "123abc_" + my_key_name
    ks.delete_records_with_name(my_key_name)

    # Add records in two batches, then delete one of the batches and make sure the other remains
    # Batch one has active and inactive keys: active = True/False, batch='one'
    # Batch two has active and inactive keys: active = True/False, batch='two'
    for i in range(4):
        for active in [True, False]:
            for batch in ["one", "two"]:
                ks.add_key(
                    name=my_key_name,
                    unencrypted_key=my_key_value,
                    active=active,
                    batch=batch,
                    source=str(i) + ", " + str(active) + ", " + batch,
                )

    """print ("Created records:")
    for r in ks.get_matching_key_records(name=my_key_name):
        print(f"    {r['name']}, {r['active']}, {r['batch']}, {r['source']}")"""

    # Delete batch one and verfiy all thats left is batch two
    ks.delete_matching_key_records(name=my_key_name, batch="one")
    # print("Remaining records after deleting batch one:")
    for r in ks.get_matching_key_records(name=my_key_name):
        # print(f"     {r['name']}, {r['active']}, {r['batch']}, {r['source']}")
        assert r["batch"] == "two", f"Expected all remaining records to be in batch two, but got {r=}"

    # Delete the inactive records and verify all thats left is batch two, active
    ks.delete_matching_key_records(name=my_key_name, active=False)
    # print("Remaining records after deleting inactive records:")
    for r in ks.get_matching_key_records(name=my_key_name):
        # print(f"     {r['name']}, {r['active']}, {r['batch']}, {r['source']}")
        assert r["batch"] == "two", f"Expected all remaining records to be in batch two, but got {r=}"
        assert r["active"] is True, f"Expected all remaining records to be active, but got {r=}"

    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_get_key_record_by_id():
    """Tests get_key_record_by_id()"""

    # Setup
    my_key_name = "test_get_key_record_by_id"
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

    new_id = ks.add_key(
        name=key_info["name"],
        unencrypted_key=key_info["key"],
        active=key_info["active"],
        batch=key_info["batch"],
        expiration_in_sse=key_info["expiration_in_sse"],
        login=key_info["login"],
        source=key_info["source"],
    )

    retrieved_record = ks.get_key_record_by_id(new_id)
    # print(f"{retrieved_record=}")
    for field in key_info.keys():
        # print(f"  Checking {field=}, {key_info[field]}, {retrieved_record[field]}")
        assert retrieved_record.get(field), f"No '{field}' in {retrieved_record=}"
        assert (
            retrieved_record[field] == key_info[field]
        ), f"Expected retrieved key value for {field} of '{key_info[field]}' but got '{retrieved_record[field]}'"


def test_tabulate_records_matching():
    # Setup
    my_key_name = "test_tabulate_records_matching"
    ks.delete_records_with_name(my_key_name)
    my_key_value = "123abc_" + my_key_name

    # Add records in two batches:
    # Batch one has active and inactive keys: active = True/False, batch='one'
    # Batch two has active and inactive keys: active = True/False, batch='two'
    new_ids = []
    for active in [True, False]:
        for batch in ["one", "two"]:
            new_ids.append(ks.add_key(name=my_key_name, unencrypted_key=my_key_value, active=active, batch=batch))

    # Tabulate the records
    tabulated = ks.tabulate_records_matching(name=my_key_name)
    #print(tabulated)
    for header in ["id", "name", "expiration_in_sse", "active", "batch", "source", "login", "encrypted_key", "key"]:
        assert header in tabulated, f"Expected {header=} in tabulated, but did not find it: \n{tabulated}"

    for id in new_ids:
        assert str(id) in tabulated, f"Expected {id=} in tabulated, but did not find it: \n{tabulated}"


if __name__ == "__main__":
    test_key_is_added_encrypted()
    test_add_and_retrieve_named_key_without_other_data()
    test_add_and_retrieve_named_key_with_all_fields()
    test_delete_matching_key_records()
    test_get_key_record_by_id()
    test_tabulate_records_matching()
