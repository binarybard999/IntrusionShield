# Importing the required modules
import os
import sys
import platform

# Automatically detecting the platform
platform = platform.system().lower()

# Asking the user for the path and file name of the python file
py_file_path = input("Enter the path and file name of the python file: ")

# Checking if the python file exists
if not os.path.isfile(py_file_path):
    print("The python file does not exist. Please enter a valid path and file name.")
    sys.exit()

# Getting the base name of the python file without extension
base_name = os.path.splitext(os.path.basename(py_file_path))[0]

# Building the command for PyInstaller
command = f"pyinstaller --onefile --name {base_name} {py_file_path}"

# Running the command
os.system(command)

# Printing a success message
if platform == "windows":
    print(f"The windowed executable file {base_name}.exe has been created in the dist folder.")
else:
    print(f"The windowed executable file {base_name} has been created in the dist folder.")
