from typing import Any
from simple_key_store import SimpleKeyStore
from datetime import datetime, timedelta


def add_key_interactive(ks: SimpleKeyStore, defaults: dict = {}):
    """Prompt user for entries to create a single key record"""
    required_fields = ["name"]
    answer = {}

    for field in ks.keystore_columns():
        if field in ["active", "encrypted_key", "expiration_in_sse", "id"]:
            continue
        answer_from_user = get_input(
            question="Enter the " + field,
            default=defaults.get(field),
            required=True if field in required_fields else False,
        )
        answer[field] = answer_from_user

    answer["active"] = True if "y" in str(get_input("Is the key active?", default="Yes")).lower() else False
    answer["expiration_in_sse"] = get_expiration_seconds_from_input(defaults.get('expiration_in_sse'))
    print(f"{answer=}")


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
    expiration_input = get_input("Enter the expiration time in number of days or a specific date (YYYY-MM-DD): ", default=default)

    if not expiration_input: return None
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
    add_key_interactive(ks)

