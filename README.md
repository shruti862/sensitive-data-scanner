
# Sensitive-data-scanner 

It is a CLI tool that scans for sensitive data in your text file and also has command utility to encrypt and decrypt the file. 


## How to Use
Open the terminal in the folder where your text file is residing and for scanning use the following command:

sensitive-data-scanner.exe scan -i input.txt -sc

For encrypting the file use the following command:

sensitive-data-scanner.exe scan -i input.txt -e -p "your_passphrase"

For decrypting the file use the following command:

sensitive-data-scanner.exe scan -i input.txt.enc -d -p "your_passphrase"

