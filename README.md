# VCM Packer✨
VCM Packer (VCM Tool) is a practical and secure tool for packing and unpacking files. This program allows you to secure your sensitive data in .vcm format using strong encryption. With a simple and user-friendly graphical user interface (GUI) based on Tkinter, it provides a secure experience for managing encrypted data.

# Outstanding security features🛡️
* Strong encryption: Uses the Fernet algorithm (based on AES-128 in CBC mode and HMAC-SHA256) to encrypt data.
* Secure Key Derivation: The encryption key is derived from the user's password using PBKDF2HMAC and a random Salt, which is highly resistant to Brute-Force and Dictionary Attacks.
* Metadata encryption: All file details (name, paths) are also encrypted so that confidential information in the vcm file is not revealed.

# Functional features🚀
* Folder Packaging: Encrypts and packages an entire folder, along with all its files and subfolders, into a .vcm file.
* VCM Unpack: Decrypts and unpacks the contents of a .vcm file to your desired location by entering the correct password.
* Graphical User Interface (GUI): Easy to use with clear buttons and input boxes.
* Standalone executable file: Can be run directly on Windows without the need to install Python and its libraries.

# Preview📸

# Install and Run🛠️
First, download the file from Release. Unzip it and run VCM Packer.exe .
<p></p>
⚠️<b>Note: Some antiviruses may mistakenly detect this file as malware due to the nature of Python file packaging and the program's interaction with the file system and clipboard. This is normal behavior for compiled Python programs. Please whitelist the file if you see such a message.</b>

# Note📣
This project was planned to be released in 2018, but due to problems encountered during the development process, its development was canceled. We are trying to keep this project alive with new features, security and bug fixes.

# Participation🤝
We welcome any contributions, bug reports, or suggestions for improvements!
* Bug Report: Report issues in the Issues section of GitHub.
* Feature Suggestion: Also submit new ideas in the Issues section.
* Code Contribution: To contribute directly to the code, please read the [Contribution Guidelines] and submit your Pull Request.

# License📄
This project is released under the MIT license.

# Contact us📞
If you have any questions or feedback, you can contact us via email.
tahanahadi@outlook.com
