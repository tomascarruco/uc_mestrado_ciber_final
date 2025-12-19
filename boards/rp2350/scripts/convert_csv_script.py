
import os
import pandas as pd

def convert_space_to_comma_csv(directory_path):
    """
    Traverses a given directory and its subdirectories, finds all .csv files,
    reads them as space-separated, and saves them back as comma-separated.
    """
    print(f"Starting conversion in directory: {directory_path}")
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.csv'):
                filepath = os.path.join(root, file)
                print(f"Processing file: {filepath}")
                try:
                    # Read the space-separated file, using a raw string for sep to avoid SyntaxWarning
                    df = pd.read_csv(filepath, sep=r'\s+', engine='python')

                    # Save the DataFrame back to the same file path as comma-separated
                    df.to_csv(filepath, index=False)
                    print(f"Successfully converted and saved: {filepath}")
                except Exception as e:
                    print(f"Error converting {filepath}: {e}")
    print(f"Conversion complete for directory: {directory_path}")

if __name__ == "__main__":
    # Prompt the user for the directory path
    user_input_directory = input("Enter the starting directory path: ")

    # Call the conversion function
    convert_space_to_comma_csv(user_input_directory)
