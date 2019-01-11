# pk1decryptor
A tool to decrypt package1s using the new TSEC crypto and/or get the TSEC keys.

## Usage
Create a folder named "pk1decryptor" at the root of the SD card.   
Inside it, put the package1 to decrypt.   
It should be named package1 if it is a retail package1, or package1_dev if it is a dev package1.   
If you just want to get the keys and do not want package1 decryption, add \_nodec to the end of the filename.  
Load pk1decryptor as a RCM payload.  
If it succeeds, you should see the keys (and package1_dec if you requested package1 decryption) in the pk1decryptor folder.   

## Credits
pk1decryptor is based on code from [Atmosphere](https://github.com/Atmosphere-NX/Atmosphere).   
The actual pk1decryptor code was made by motezazer.   
Special thanks to SciresM for his help, which sped up the research leading to the creation of this software.
