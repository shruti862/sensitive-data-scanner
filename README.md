# sensitive-data-scanner
It is a CLI tool that scans for sensitive data in your text file and also has command utility to encrypt and decrypt the file. 
For scanning purpose run this command on your terminal :
sensitive-data-scanner.exe scan -i input.txt -sc
For encrypting the file:
 sensitive-data-scanner.exe scan -i input.txt -e -p "your_passphrase"
For decrypting the file:
sensitive-data-scanner.exe scan -i input.txt.enc -d -p "your_passphrase"
