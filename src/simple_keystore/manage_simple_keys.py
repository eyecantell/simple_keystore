from typing import Any, Dict, List, Tuple
from simple_keystore import SimpleKeyStore
from datetime import datetime, timedelta
import argparse
import os


def show_records(ks: SimpleKeyStore, records: List):
    headers = ["id"] + ks.set_defining_fields + ["expiration_date", "expired", "usable", "key"]
    print(ks.tabulate_records(records, headers))


def manage_keys(ks: SimpleKeyStore, defaults: dict = {}):
    """Offer CLI interactive menu to manage keys"""
    new_records_list = []
    use_last_answer_as_default = False if defaults else True
    # print(f"{use_last_answer_as_default=}")

    while True:
        all_records = ks.get_matching_key_records()
        print(f"Currently have {len(all_records)} records in {ks.name}")

        menu_items = [
            f"[A] Add new key to {ks.name}",
            "[D] Delete a key",
            f"[L] List all {len(all_records)} keys in {ks.name}",
            "[N] Mark key inactive, and get next available.",
            f"[S] List the {len(new_records_list)} keys created this session.",
            "[U] Show usability counts report",
            "[V] TODO Delete unusable (inactive or expired) keys",
            "[X] Exit",
        ]

        menu_string = "\n".join(menu_items)
        choice = str(get_input(f"{menu_string}\n--\nWhat would you like to do?", default="X")).upper()

        if choice == "A":
            # Add a new key
            new_record, answer = add_single_key_interactive(ks, defaults)

            if use_last_answer_as_default:
                # Set the defaults for the next key based on the answer given for the previous key
                defaults = answer
                print(f"{defaults=}")
                del defaults["unencrypted_key"]

            # Add the new record to our list of records and show the list of created records
            new_records_list.append(new_record)
            show_records(ks, new_records_list)

        elif choice == "D":
            key_to_delete = get_input("Enter key that should be deleted")
            print(f"Will delete {key_to_delete=}")
            number_of_keys_deleted = ks.delete_key_record(unencrypted_key=key_to_delete)
            print(f"{number_of_keys_deleted} keys deleted.")

        elif choice == "L":
            # List all keys in the db
            print(f"All records in {ks.name}")
            ks.records_for_usability_report(print_records=True)

        elif choice == "M":
            # Mark the given key active
            key_to_make_active = get_input("Enter key that should be made active")
            record = ks.get_key_record(key_to_make_active)
            if not record:
                print(f"Did not find a record with key {key_to_make_active}")
                continue
            number_of_keys_updated = ks.mark_key_active(key_to_make_active)
            print(f"{number_of_keys_updated} keys updated to active.")

        elif choice == "N":
            # Mark the given key inactive and get the next available key
            key_to_make_inactive = get_input("Enter key that should be made inactive")
            record = ks.get_key_record(key_to_make_inactive)
            if not record:
                print(f"Did not find a record with key {key_to_make_inactive}")
                continue
            number_of_keys_updated = ks.update_key(id_to_update=record["id"], active=False)
            print(f"{number_of_keys_updated} keys updated to inactive.")
            next_key = ks.get_next_usable_key(name=record.get("name"))
            if next_key is None:
                print(f"No keys left with name {record['name']}")
            else:
                print(f"Next available key with name {record['name']} is:\n{next_key}")

        elif choice == "S":
            # Show keys created this session
            print("Records created this session", ks.name)
            show_records(ks, new_records_list)

        elif choice == "X":
            break

        elif choice == "U":
            ks.usability_counts_report(print_counts=True)


def add_single_key_interactive(ks: SimpleKeyStore, defaults: dict = {}) -> Tuple[Dict, Dict]:
    """Prompt user for entries to create a single key record. Returns a dict of the new record values, and the answers given."""
    required_fields = ["name"]
    answer = {}

    for field in ks.keystore_columns() + ["unencrypted_key"]:
        if field in ["active", "encrypted_key", "expiration_in_sse", "id"]:
            continue
        answer_from_user = get_input(
            question="Enter the " + field,
            default=defaults.get(field),
            required=True if field in required_fields else False,
        )
        answer[field] = answer_from_user

    answer["active"] = True if "y" in str(get_input("Is the key active?", default="Yes")).lower() else False
    expiration_in_sse, expiration_input = get_expiration_seconds_from_input(defaults.get("expiration_input"))
    answer["expiration_input"] = expiration_input
    print(f"{answer=}")

    new_id = ks.add_key(
        name=answer["name"],
        unencrypted_key=answer["unencrypted_key"],
        active=answer["active"],
        expiration_in_sse=expiration_in_sse,
        batch=answer["batch"],
        source=answer["source"],
        login=answer["login"],
    )

    new_record = ks.get_key_record_by_id(new_id)
    return new_record, answer


# Now you can use these values to insert a new record into the database
def get_input(question: str, required: bool = False, default: Any = None) -> Any:
    answer = None
    while not answer:
        answer = input(question + " [" + str(default) + "] ")
        if not answer:
            answer = default
        if required and not answer:
            print("Required field, please enter a value...")
        else:
            return answer


def get_expiration_seconds_from_input(default) -> Tuple[int, str]:
    """Gets user input for expiration date. Returns seconds since epoch and answer given"""
    expiration_input = get_input(
        "Enter the expiration time in number of days or a specific date (YYYY-MM-DD): ", default=default
    )

    if not expiration_input:
        return None
    try:
        # Attempt to parse input as an integer (days)
        expiration_days = int(expiration_input)
        expiration_date = datetime.now() + timedelta(days=expiration_days)
    except ValueError:
        # If input is not an integer, assume it is a date in format YYYY-MM-DD
        expiration_date = datetime.strptime(expiration_input, "%Y-%m-%d")

    expiration_seconds = int(expiration_date.timestamp())

    return expiration_seconds, expiration_input


def main():
    parser = argparse.ArgumentParser(usage="python manage_keys.py [keystore.db]", description="Simple keystore manager")

    # Add the argument for the keystore db
    parser.add_argument("keystore_db", help="The keystore database to manage")

    args = parser.parse_args()
    if not os.path.isfile(args.keystore_db):
        raise RuntimeError(f"Cannot locate keystore db: {args.keystore_db}")

    ks = SimpleKeyStore(args.keystore_db)
    manage_keys(ks)


if __name__ == "__main__":
    main()
