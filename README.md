# VirusTotal File Checker Script

## Introduction

The VirusTotal File Checker Script calculates the MD5 hash of files in a specified directory and checks their status using the VirusTotal API. It outputs the VirusTotal report for each file to a text file. This script is useful for automating the process of checking files for malware or other issues using VirusTotal's extensive database.

## Features

- **MD5 Hash Calculation**: Computes the MD5 hash for each file in the specified directory.
- **VirusTotal Integration**: Uses the VirusTotal API to check the status of each file based on its MD5 hash.
- **Output Reports**: Saves the VirusTotal report for each file to a text file for further review.

## Prerequisites

- Python 3.6 or higher.
- VirusTotal API key.
- Required Python libraries: `os`, `json`, `hashlib`, `virus_total_apis`.

## Modules

- **os**: Provides functions for interacting with the operating system.
- **json**: Allows for parsing and manipulating JSON data.
- **hashlib**: Provides functions for creating secure hash and message digest algorithms.
- **virus_total_apis**: Provides an interface to the VirusTotal API.

```python
import os
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
```

## Configuration

### VirusTotal API Key

Store your VirusTotal API key as a string variable:

```python
API_KEY = 'your_api_key_here'
```

### Target Folder

Define the path to the folder containing the files you want to check:

```python
TARGET_FOLDER = 'path_to_your_target_folder'
```

### Output File

Define the path and name of the file where you want to save the output:

```python
OUTPUT_FILE = 'output.txt'
```

## Functions

### `get_md5_hash(file_path)`

Calculates the MD5 hash of a file.

- **Parameters:**
  - `file_path` (str): The path to the file.
- **Returns:**
  - `str`: The MD5 hash of the file.

#### Example

```python
def get_md5_hash(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        chunk = f.read()
        hash_md5.update(chunk)
    return hash_md5.hexdigest()
```

### `main()`

The main function that orchestrates the file checking process.

- **Returns:**
  - `None`

#### Example

```python
def main():
    vt = VirusTotalPublicApi(API_KEY)
    with open(OUTPUT_FILE, 'w') as output_file:
        for filename in os.listdir(TARGET_FOLDER):
            file_path = os.path.join(TARGET_FOLDER, filename)
            if os.path.isfile(file_path):
                file_hash = get_md5_hash(file_path)
                response = vt.get_file_report(file_hash)
                output_file.write(json.dumps(response, sort_keys=False, indent=4))
                output_file.write('\n\n')
```

## Usage

1. **Install Required Libraries**: Ensure the required libraries are installed.

    ```bash
    pip install virus_total_apis
    ```

2. **Set Up Configuration**: Update the `API_KEY`, `TARGET_FOLDER`, and `OUTPUT_FILE` variables with your VirusTotal API key, target folder path, and desired output file name.

    ```python
    API_KEY = 'your_api_key_here'
    TARGET_FOLDER = 'path_to_your_target_folder'
    OUTPUT_FILE = 'output.txt'
    ```

3. **Run the Script**: Execute the script in your Python environment.

    ```bash
    python script_name.py
    ```

4. **Review the Output**: The script will generate an output file containing the VirusTotal report for each file in the specified directory.

## Example Output

The output file will contain JSON-formatted VirusTotal reports for each file, similar to the following:

```json
{
    "response_code": 1,
    "verbose_msg": "Scan finished, information embedded",
    "resource": "44d88612fea8a8f36de82e1278abb02f",
    "scan_id": "44d88612fea8a8f36de82e1278abb02f-1592239502",
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
    "sha256": "275a021bbfb648ba4b234d013adf79735d6c5e24d5db663b3b5e2e864f2d1539",
    "scan_date": "2020-06-15 20:05:02",
    "positives": 0,
    "total": 57,
    "scans": {
        "Bkav": {
            "detected": false,
            "version": "1.3.0.9899",
            "result": null,
            "update": "20200615"
        },
        ...
    }
}
```

## Error Handling

- **Invalid API Key**: Ensure your API key is valid and has the necessary permissions.
- **File Access Errors**: Ensure the script has read access to the target folder and write access to the output file location.
- **API Rate Limits**: Be mindful of VirusTotal's API rate limits and handle responses accordingly.

## Security Considerations

- **API Key Security**: Keep your VirusTotal API key secure and do not share it publicly.
- **File Privacy**: Ensure the files being scanned do not contain sensitive information if sharing reports.

## FAQs

**Q: What happens if the VirusTotal API rate limit is exceeded?**
A: The script may receive a response indicating the rate limit has been exceeded. Handle such responses by implementing retry logic or pausing the script.

**Q: Can I use a different hashing algorithm?**
A: The script currently uses MD5 for hashing. You can modify the `get_md5_hash` function to use a different algorithm supported by VirusTotal, such as SHA-1 or SHA-256.

**Q: How can I check more than one directory?**
A: Modify the script to iterate through multiple directories or update the `TARGET_FOLDER` variable with a different directory path.

## Troubleshooting

- **Module Not Found Errors**: Ensure Python is installed correctly and all necessary modules are available. Install any missing modules using `pip`.
- **File Not Found**: Ensure the target folder and output file paths are correct.

## Detailed Instructions

1. **Install Required Libraries**: Ensure the `virus_total_apis` library is installed. This library is used to interact with the VirusTotal API. If you haven't installed it yet, run the following command:

    ```bash
    pip install virus_total_apis
    ```

2. **Set Up Configuration**: Before running the script, you need to configure the following variables:
    - **API_KEY**: Replace `'your_api_key_here'` with your actual VirusTotal API key.
    - **TARGET_FOLDER**: Replace `'path_to_your_target_folder'` with the path to the directory containing the files you want to check.
    - **OUTPUT_FILE**: Replace `'output.txt'` with the desired path and name of the output file.

    ```python
    API_KEY = 'your_api_key_here'
    TARGET_FOLDER = 'path_to_your_target_folder'
    OUTPUT_FILE = 'output.txt'
    ```

3. **Run the Script**: Once the configuration is set, execute the script in your Python environment. The script will iterate over all files in the specified directory, calculate their MD5 hashes, check their status using the VirusTotal API, and save the results to the output file.

    ```bash
    python script_name.py
    ```

4. **Review the Output**: Open the output file to review the VirusTotal reports for each file in the specified directory. The reports are saved in JSON format for easy readability and further processing.

## Example Output

The output file will contain JSON-formatted VirusTotal reports for each file, similar to the following example:

```json
{
    "response_code": 1,
    "verbose_msg": "Scan finished, information embedded",
    "resource": "44d88612fea8a8f36de82e1278abb02f",
    "scan_id": "44d88612fea8a8f36de82e1278abb02f-1592239502",
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
    "sha256": "275a021bbfb648ba4b234d013adf79735d6c5e24d5db663b3b5e2e864f2d1539",
    "scan_date": "2020-06-15 20:05:02",
    "positives": 0,
    "total": 57,
    "scans": {
        "Bkav": {
            "detected": false,
            "version": "1.3.0.9899",
            "result": null,
            "update": "20200615"
        },
        ...
    }
}
```

## Error Handling

- **Invalid API Key**: If your API key is invalid or lacks necessary permissions, the script will not be able to retrieve reports from VirusTotal. Ensure your API key is correct and has the required

 permissions.
- **File Access Errors**: Ensure the script has appropriate permissions to read files from the target folder and write to the output file location. If there are permission issues, the script will fail to access these files.
- **API Rate Limits**: VirusTotal imposes rate limits on API usage. If the rate limit is exceeded, the script may receive a response indicating this. Implement retry logic or add delays to handle such cases.

## Security Considerations

- **API Key Security**: Your VirusTotal API key is sensitive information. Keep it secure and avoid sharing it publicly or in insecure locations.
- **File Privacy**: The files being checked by the script may contain sensitive information. Ensure you have the necessary permissions to scan these files and handle their reports securely.

## FAQs

**Q: What happens if the VirusTotal API rate limit is exceeded?**
A: If the rate limit is exceeded, the script may receive a response indicating the rate limit has been hit. Implement retry logic or pause the script to handle such cases.

**Q: Can I use a different hashing algorithm?**
A: The script currently uses MD5 for hashing. You can modify the `get_md5_hash` function to use a different algorithm supported by VirusTotal, such as SHA-1 or SHA-256.

**Q: How can I check more than one directory?**
A: To check multiple directories, you can modify the script to iterate through a list of directories or update the `TARGET_FOLDER` variable to point to a different directory path.

**Q: Why is my output file empty?**
A: Ensure that there are files in the target directory and that the script has the necessary permissions to read these files and write to the output file.

## Troubleshooting

- **Module Not Found Errors**: If you encounter module not found errors, ensure Python is installed correctly and all necessary modules are available. Use `pip` to install any missing modules.
- **File Not Found**: Verify that the target folder and output file paths are correct. Ensure that the files exist in the target directory and that the paths are specified correctly in the script.

For further assistance or to report bugs, please reach out to the repository maintainers or open an issue on the project's issue tracker.
