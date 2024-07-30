from simple_key_store import SimpleKeyStore
from datetime import datetime, timedelta

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
    records = ks.get_matching_key_records(name=my_key_name)
    tabulated = ks.tabulate_records(records)
    print(tabulated)
    for header in ["id", "name", "expiration_in_sse", "active", "batch", "source", "login", "encrypted_key", "key"]:
        assert header in tabulated, f"Expected {header=} in tabulated, but did not find it: \n{tabulated}"

    for id in new_ids:
        assert str(id) in tabulated, f"Expected {id=} in tabulated, but did not find it: \n{tabulated}"


def test_get_matching_key_records_no_args():
    """If no args are given to get_matching_key_records, we expect to get all records"""
    # Setup
    my_key_name = "test_get_matching_key_records_no_args"

    my_key_value = "123abc_" + my_key_name

    # Add some records
    num_records_to_create = 5
    for i in range(num_records_to_create):
        ks.add_key(name=my_key_name, unencrypted_key=my_key_value, batch=str(i))

    matching_records = ks.get_matching_key_records()
    num_records_in_db = ks.number_of_records()

    assert (
        len(matching_records) >= num_records_to_create
    ), f"Expected at least {num_records_to_create} matching records, but got {len(matching_records)}"
    assert (
        num_records_in_db >= num_records_to_create
    ), f"Expected at least {num_records_to_create} records in db, but got {num_records_in_db}"
    assert num_records_in_db == len(
        matching_records
    ), f"Expected same number of records, but got {num_records_in_db=} and {len(matching_records)=}"

    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_get_key_record():
    """Get a specific key by giving hte unencrypted key value"""
    # Setup
    my_key_name = "test_get_key_record"

    my_key_value = "123abc_" + my_key_name

    # Add the key
    new_id = ks.add_key(name=my_key_name, unencrypted_key=my_key_value)
    assert new_id, "Failed to add key"

    # Get the record from the db
    key_record = ks.get_key_record(unencrypted_key=my_key_value)
    # print(f"{key_record=}")

    assert key_record, "Failed to retrieve added key"
    assert key_record.get("key") == my_key_value, f"Expected {my_key_value=}, but got {key_record.get('key')}"

    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_encrypt_and_decrypt():
    keys_to_test = [
        "gAAAAABmp7N54OH60IYC5mrY1nRowyHaw39d3C6zY",
        "123abc_my_test",
        "1",
        "a",
    ]

    # Encrypt and decrypt each key
    for unencrypted_key in keys_to_test:
        encrypted_key = ks.encrypt_key(unencrypted_key)
        decrypted_key = ks.decrypt_key(encrypted_key)
        assert unencrypted_key == decrypted_key, f"Expected {unencrypted_key} but got {decrypted_key}"


def test_records_sorted_for_batch_report():
    # Setup
    my_key_name = "test_records_sorted_for_batch_report"
    ks.delete_records_with_name(my_key_name)
    my_key_value = "123abc_" + my_key_name

    # Add records in two batches:
    # Batch one has active and inactive keys: active = True/False, batch='one'
    # Batch two has active and inactive keys: active = True/False, batch='two'
    new_ids = []
    expiration_in_sse = 1234567890
    for login in ["login1", "login2"]:
        for active in [True, False]:
            for batch in ["one", "two"]:
                new_ids.append(
                    ks.add_key(
                        name=my_key_name,
                        unencrypted_key=my_key_value,
                        active=active,
                        batch=batch,
                        login=login,
                        expiration_in_sse=expiration_in_sse,
                    )
                )
                expiration_in_sse += 1000

    # Get the report and check the expected values
    records = ks.records_for_usability_report(key_name=my_key_name, print_records=False)
    for r in records:
        assert r.get("name") == my_key_name

    for i in range(4):
        # print(f"{records[i]=}")
        assert records[i].get("login") == "login1", f"Expected record {i} login to be 'login1', but got {records[i]}"
        assert (
            records[i + 4].get("login") == "login2"
        ), f"Expected record {i+4} login to be 'login2', but got {records[i+4]}"

    for i in [0, 1, 4, 5]:
        assert records[i].get("batch") == "one", f"Expected record {i} batch to be 'one', but got {records[i]}"
        assert records[i + 2].get("batch") == "two", f"Expected record {i+2} batch to be 'two', but got {records[i+2]}"

    # Clean up
    ks.delete_records_with_name(my_key_name)


def test_usability_report():
    # Setup
    my_key_name = "test_usability_report"
    ks.delete_records_with_name(my_key_name)
    my_key_value = "123abc_" + my_key_name

    # Add records
    new_ids = []
    yesterday = datetime.today() + timedelta(days=-1)
    tomorrow = datetime.today() + timedelta(days=1)

    for login in ["login1", "login2"]:
        for source in ["a.com", "b.com", "c.com"]:
            for expiration_date in [yesterday, tomorrow]:
                for active in [True, False]:
                    for batch in ["one", "two"]:
                        for i in range(3):
                            new_ids.append(
                                ks.add_key(
                                    name=my_key_name,
                                    unencrypted_key=my_key_value + str(i),
                                    active=active,
                                    batch=batch,
                                    expiration_in_sse=expiration_date.timestamp(),
                                    login=login,
                                    source=source,
                                )
                            )

    # Get the report and check the expected values
    usability_records = ks.usability_counts_report(key_name=my_key_name, print_records=True, print_counts=True)

    assert len(usability_records) == 12, f"Expected 12 records, but got {len(usability_records)}"

    # First four should be a.com, then b.com, c.com
    for i in range(4):
        # print(f"{records[i]=}")
        assert (
            usability_records[i].get("source") == "a.com"
        ), f"Expected record {i} source to be 'a.com', but got {usability_records[i].get('source')}"
        assert (
            usability_records[i + 4].get("source") == "b.com"
        ), f"Expected record {i+4} source to be 'b.com', but got {usability_records[i+4].get('source')}"
        assert (
            usability_records[i + 8].get("source") == "c.com"
        ), f"Expected record {i+8} source to be 'c.com', but got {usability_records[i+4].get('source')}"

    # Should get two each of login1, login2
    for i in [0, 1, 4, 5, 8, 9]:
        assert (
            usability_records[i].get("login") == "login1"
        ), f"Expected record {i} login to be 'login1', but got {usability_records[i].get('login')}"
        assert (
            usability_records[i + 2].get("login") == "login2"
        ), f"Expected record {i+2} login to be 'login2', but got {usability_records[i+2].get('login')}"

    for i in range(12):
        batch = "two" if i % 2 else "one"
        assert (
            usability_records[i].get("batch") == batch
        ), f"Expected record {i} batch to be 'login1', but got {usability_records[i].get('batch')}"
        assert (
            usability_records[i].get("usable") == 3
        ), f"Expected record {i} usable count to be 3, but got {usability_records[i].get('usable')}"
        assert (
            usability_records[i].get("unusable") == 9
        ), f"Expected record {i} unusable count to be 9, but got {usability_records[i].get('unusable')}"

    # Clean up
    ks.delete_records_with_name(my_key_name)


if __name__ == "__main__":
    test_encrypt_and_decrypt()
    test_key_is_added_encrypted()
    test_add_and_retrieve_named_key_without_other_data()
    test_add_and_retrieve_named_key_with_all_fields()
    test_delete_matching_key_records()
    test_get_key_record_by_id()
    test_tabulate_records_matching()
    test_get_matching_key_records_no_args()
    test_get_key_record()
    test_records_sorted_for_batch_report()
    test_usability_report()
