import os
import subprocess
import argparse
import json

"""
This scripts generates cache files for notebooks.

Requirements:
- jupyter-nbconvert package
"""

CACHE_DIR = "./cache"
TOPICS_FILENAME = "topics.json"

def process_notebook(notebook_path:str, debug:bool=False) -> int:
    """
    Process a notebook to generate a cache file.

    Args:
        notebook_path (str): The relative path of the notebook to process, from the root of the repository

    Returns:
        int: The size of the cache file in bytes
    """

    cache_size = 0

    # Get the name of the notebook
    notebook_name = os.path.basename(notebook_path)
    notebook_name = notebook_name.split(".")[0]
    target_name   = notebook_name + "-ipynb.md.cache"
    target_path   = os.path.join(CACHE_DIR, os.path.dirname(notebook_path), target_name)

    # Get the last modified time of the notebook and the cache file
    try:
        notebook_mtime = os.path.getmtime(notebook_path)
        cache_mtime = os.path.getmtime(target_path)
        cache_size = os.path.getsize(target_path)
    except FileNotFoundError:
        cache_mtime = 0
    except Exception as e:
        print(f"ERROR: Failed to process {notebook_path}: {e}")
        return 0
    
    # If the notebook is older than the cache file, skip the processing
    if notebook_mtime <= cache_mtime:
        if debug:
            print(f"Skipping {notebook_path} because it is older than the cache file")
        return cache_size

    # Create the directory if it doesn't exist
    if not os.path.exists(os.path.dirname(target_path)):
        os.makedirs(os.path.dirname(target_path))

    # Read the content of the notebook
    with open(notebook_path, "rb") as f:
        input_content = f.read()

    # Generate the cache file
    try:
        proc = subprocess.run(['jupyter-nbconvert', '--to', 'markdown', '--stdin', '--stdout'], input=input_content, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"ERROR: Failed to process {notebook_path}: {e}")
        return
    output_content = proc.stdout

    # Write the cache file
    with open(target_path, "wb") as f:
        f.write(output_content)

    if debug:
        print(f"Processed {notebook_path} to {target_path}")

    return len(output_content)


def process_directory(dir_path:str, debug:bool=False) -> int:
    """
    Process a directory to generate cache files for the notebooks. Then, process the subdirectories recursively.

    Args:
        dir_path (str): The relative path of the directory to process, from the root of the repository

    Returns:
        int: The size of the cache files in bytes
    """
    cache_size = 0

    if debug:
        print(f"Processing directory {dir_path}")

    # Read the content of the directory
    sub_file = os.listdir(dir_path)

    # Get the list of notebooks
    notebooks = [f for f in sub_file if f.endswith(".ipynb")]

    # Process the notebooks
    for notebook in notebooks:
        cache_size += process_notebook(os.path.join(dir_path, notebook), debug)

    # Process the subdirectories. If there is a topic.json file, process it, else process the subdirectories
    if TOPICS_FILENAME in sub_file:
        with open(os.path.join(dir_path, TOPICS_FILENAME), "r") as f:
            subdirs = json.load(f)
    else:
        subdirs = [f for f in sub_file if os.path.isdir(os.path.join(dir_path, f))]
    for subdir in subdirs:
        cache_size += process_directory(os.path.join(dir_path, subdir), debug)

    return cache_size


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate cache files for notebooks")
    parser.add_argument("--debug", action="store_true", help="Print debug information")
    args = parser.parse_args()

    # Check if jupyter-nbconvert is present
    try:
        proc = subprocess.run(['jupyter-nbconvert', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("WARNING: jupyter-nbconvert is not installed, skipping cache generation")
        exit(1)

    # Create cache directory if it doesn't exist
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    # Process the notebooks
    cache_size = process_directory(".", args.debug)
    if args.debug:
        cache_size = cache_size / 1024**2
        cache_size = round(cache_size, 2)
        print(f"Cache files generated. Total size: {cache_size} MB")