# ADVANCED-ENCRYPTION-TOOL

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: ANSARI MOHD TAKI

*INTERN ID*: CT04DL765

*DOMAIN*: CYBER SECURITY & ETHICAL HACKING

*DURATION*: 4 WEEKS

*MENTOR*: NEELA SANTOSH

*DISCRIPTION*:  

As part of my efforts to better understand applied cryptography and secure file handling, I developed a Python-based AES-256 file encryption and decryption utility. The aim of this project was to create a practical solution for protecting sensitive files using strong encryption standards. With the rise of data breaches and privacy concerns, building such a tool allowed me to address real-world needs while enhancing my technical skills.

The core functionality of the program is centered around the Advanced Encryption Standard (AES) with a 256-bit key length operating in CBC (Cipher Block Chaining) mode. This mode, while powerful, requires additional precautions for secure implementation. To convert a user-provided password into a strong encryption key, I used PBKDF2HMAC (Password-Based Key Derivation Function 2) combined with SHA-256. A unique salt is generated for each operation, which, along with 100,000 iterations, ensures that the derived keys are unique and resistant to brute-force attacks. I also generate a 16-byte Initialization Vector (IV) randomly, as required by CBC mode to maintain unpredictability.

For encryption, the user is prompted to specify the input and output file paths, along with a secure password. The script reads the input file in binary format, applies PKCS7 padding to meet AES block size requirements, and encrypts the data using the generated key and IV. The final output file contains the salt, IV, and ciphertext. The decryption process follows the reverse flow — extracting the salt and IV, regenerating the key, decrypting the content, and removing padding before writing the plaintext back to a file. The tool gracefully handles errors, such as incorrect passwords or file corruption, with clear user messages instead of technical tracebacks.

I developed and tested this project using both Trea and Python’s built-in IDLE environment. These platforms offered smooth debugging capabilities and helped manage file path configurations efficiently.

This encryption tool can be employed in various scenarios. Individuals can use it to secure personal documents like tax records or ID scans. Small businesses may find it helpful for encrypting internal reports before distribution. Freelancers can use it to send sensitive client deliverables safely, and students working on collaborative projects can ensure confidentiality when sharing academic data.

Throughout the development process, I relied on several reputable sources to guide me. I referred to GeeksforGeeks for a conceptual overview of AES and key derivation. Real Python provided practical examples of handling encryption in Python, and the Cryptography.io official documentation was instrumental in understanding the correct usage of cryptographic primitives. Stack Overflow proved extremely helpful in resolving runtime issues and interpreting error messages.

This project allowed me to combine theoretical knowledge with hands-on development to produce a secure and user-friendly encryption tool. Looking ahead, I plan to expand the project by adding a graphical user interface and possibly integrating authenticated encryption modes like AES-GCM to ensure both confidentiality and integrity. Building this tool reinforced my commitment to creating secure applications with a focus on usability and reliability.

*OUTPUT*
