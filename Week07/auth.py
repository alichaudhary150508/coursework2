import bcrypt
import os

# Hash password
def hash_password(plain_text_pass):
    pass_bytes = plain_text_pass.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_pass = bcrypt.hashpw(pass_bytes, salt)
    return hashed_pass

# Verify password
def verify_password(plain_text_pass, hashed_pass):
    plain_text_pass = plain_text_pass.encode("utf-8")
    result = bcrypt.checkpw(plain_text_pass, hashed_pass)
    return result

# Temporary test code - Remove after testing
test_password = "SecurePassword123"
# Test hashing
hashed = hash_password(test_password)
print(f"Original password: {test_password}")
print(f"Hashed password: {hashed}")
print(f"Hash length: {len(hashed)} characters")

# Test verification
is_valid = verify_password(test_password, hashed)
print(f"\nVerification with correct password: {is_valid}")

# Test verification with incorrect password
is_invalid = verify_password("WrongPassword", hashed)
print(f"Verification with incorrect password: {is_invalid}")

USER_DATA_FILE = "user.txt"

# Register user function
def register_user(username, password):
    # Check if the user data file exists
    if not os.path.exists(USER_DATA_FILE):
        # If the file doesn't exist, create it
        with open(USER_DATA_FILE, "w"):
            pass  # Just create the empty file

    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, _ = line.strip().split(":")
            if stored_username == username:
                return False  # Username already exists

    # Hash the password
    hashed_password = hash_password(password)

    # Append the new user to the file
    with open(USER_DATA_FILE, "a") as file:
        file.write(f"{username}:{hashed_password.decode('utf-8')}\n")

    return True  # Registration successful

# Check if user exists
def user_exists(username):
    try:
        with open(USER_DATA_FILE, "r") as file:
            for line in file:
                stored_username, _ = line.strip().split(":")
                if stored_username == username:
                    return True  # User already exists
    except FileNotFoundError:
        return False  # If the file doesn't exist

    return False  # User not found

# Login function
def login_user(username, password):
    # Check if the user data file exists
    if not os.path.exists(USER_DATA_FILE):
        print("No users registered yet.")
        return False

    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, stored_hashed_password = line.strip().split(":")
            if stored_username == username:
                # If username matches, verify the password
                is_valid = verify_password(password, stored_hashed_password.encode("utf-8"))
                if is_valid:
                    print("Login successful!")
                    return True
                else:
                    print("Incorrect password!")
                    return False

    print("Username was not found.")
    return False

# Username validation
def validate_username(username):
    if len(username) < 5:
        return False, "Username must be at least 5 characters long."
    if len(username) > 20:
        return False, "Username must be no longer than 20 characters."
    return True, ""

# Password validation
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    return True, ""

# Display menu
def display_menu():
    print("\n" + "=" * 50)
    print("  MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("  Secure Authentication System")
    print("=" * 50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-" * 50)

# Main function
def main():
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()

            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register the user
            if register_user(username, password):
                print(f"User {username} successfully registered!")
            else:
                print(f"Error: Username {username} already exists.")

        elif choice == '2':
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            if login_user(username, password):
                print(f"\nYou are now logged in {username}.")
                print("(In a real application, you would now access the data)")

                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to return to main menu...")

        elif choice == '3':
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()