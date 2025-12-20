
import os

def remove_quotes_from_files(directory_path):
    """
    Traverses a given directory and its subdirectories, finds all files,
    reads their content, removes double quotes, and saves them back.
    """
    print(f"Starting quote removal in directory: {directory_path}")
    for root, _, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            print(f"Processing file for quote removal: {filepath}")
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Remove double quotes
                modified_content = content.replace('"', '')

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(modified_content)
                print(f"Successfully removed quotes from: {filepath}")
            except Exception as e:
                print(f"Error removing quotes from {filepath}: {e}")
    print(f"Quote removal complete for directory: {directory_path}")

if __name__ == "__main__":
    # Prompt the user for the directory path
    user_input_directory = input("Enter the starting directory path: ")

    # Call the quote removal function
    remove_quotes_from_files(user_input_directory)
