from typing import Any, Dict
from simple_key_store import SimpleKeyStore
from datetime import datetime, timedelta


def manage_keys(ks: SimpleKeyStore, defaults: dict = {}):
    '''Offer CLI interactive menu to manage keys'''
    new_records_list = []
    use_last_answer_as_default = False if defaults else True
    print(f"{use_last_answer_as_default=}")

    while True:
        all_records = ks.get_matching_key_records()

        menu_items = [
            f"[N] Add new key to {ks.name}",
            f"[A] List all {len(all_records)} keys in {ks.name}",
            f"[S] List the {len(new_records_list)} keys created this session.",
            "[D] Delete a key",
            "[X] Exit",
        ]

        menu_string = "\n".join(menu_items)
        choice = str(get_input(f"{menu_string}--\nWhat would you like to do (N,A,S,X)?", default="X")).upper()

        if choice == "N":
            new_record = add_single_key_interactive(ks, defaults)

            if use_last_answer_as_default:
                # Set the defaults for the next key based on the data for the previous key
                for field in new_record.keys():
                    if field in ["encrypted_key", "key"]:
                        continue
                    defaults[field] = new_record[field]

            # Add the new record to our list of records and show the list of created records
            new_records_list.append(new_record)
            print(ks.tabulate_records(new_records_list))

        elif choice == "A":
            # Show all keys in the db
            print("All records in", ks.name)
            ks.tabulate_records(all_records)

        elif choice == "S":
            # Show keys created this session
            print("Records created this session", ks.name)
            ks.tabulate_records(new_records_list)

        elif choice == "X":
            break
        elif choice == "D":
            key_to_delete = get_input("Enter key that should be deleted")
            number_of_keys_deleted = ks.delete_key_record(unencrypted_key=key_to_delete)
            print(f"{number_of_keys_deleted} keys deleted.")
            


def add_single_key_interactive(ks: SimpleKeyStore, defaults: dict = {}) -> Dict:
    """Prompt user for entries to create a single key record. Returns a dict of the new record values."""
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
    answer["expiration_in_sse"] = get_expiration_seconds_from_input(defaults.get("expiration_in_sse"))
    print(f"{answer=}")

    new_id = ks.add_key(
        name=answer["name"],
        unencrypted_key=answer["unencrypted_key"],
        active=answer["active"],
        expiration_in_sse=answer["expiration_in_sse"],
        batch=answer["batch"],
        source=answer["source"],
        login=answer["login"],
    )

    new_record = ks.get_key_record_by_id(new_id)
    return new_record


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


def get_expiration_seconds_from_input(default) -> int:
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

    return expiration_seconds


if __name__ == "__main__":
    ks = SimpleKeyStore("interactive_test")
    manage_keys(ks)
