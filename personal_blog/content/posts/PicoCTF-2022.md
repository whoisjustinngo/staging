+++
title = 'PicoCTF 2022'
date = 2023-11-26
draft = true
tags = ['coding', 'ctf', 'cybersecurity']
math = true
+++

## Binary Exploitation

### basic-file-exploit (100)

If we take a look at the source code, the redacted flag is stored in a variable `flag`. `flag` is only ever referenced one other time, in the `data_read()` function. The `data_read()` function is only called by `main()` when the user specifies option '2' to echo a phrase stored in the database **and** when there is at least 1 phrase already stored in the database. When `data_read()` is called, it asks the user to specify the index number of the entry the user wants to be echoed, which is stored in the variable `entry_number`. If `entry_number` is 0, the `flag` is written to stdout by the `puts()` function.

Therefore, to retrieve the flag, all we have to do is:

1. Store at least 1 phrase in the database.
2. Request the program to echo a stored phrase.
3. Enter 0 when the program asks for the index number of the phrase to be echoed.

### buffer overflow 0 (100)

Looking at the source code, we find that the flag will be printed out when a segmentation fault occurs. If we look at the man page for `gets()` as hinted, we find out that `gets()` should never be used because there is a risk of buffer overrun. `gets()` is called in `main()` to read the value input by the user when they are asked and stores in the value in `buf1`, which is declared with a maximum size of 100. This input is then passed to the `vuln()` function, where it is copied into `buf2` which is declared with a size of 16. This means that we should be able to cause a buffer overflow and trigger a segmentation fault if our input is more than 16 characters long.

Sure enough, an input string of 20 characters long is enough to trigger a segmentation fault and cause the flag to be printed (I'm not exactly sure why 17 characters isn't sufficient, could be due to how the data is actually stored in memory).

### RPS (200)

If we look at the main function in the source code, we see that it uses a variable `wins` to keep track of the number of consecutive wins by the player. If the player requests to play a round by entering '1', the `play()` function is called. If `play()` returns `true`, i.e. the player wins, then `wins` is incremented, and if it returns `false` then `wins` is reset to 0. There doesn't appear to be anything here which could be easily exploitable.

If we look at the `play()` function, it uses the `tgetinput()` helper function to get and handle the player's choice. Quick analysis of the `tgetinput()` functioin shows that it doesn't do any input validation beyond just checking if the user entered anything at all. This means that we can type anything and our input will still be passed back to `play()` to do the scoring:

![Lack of input validation](/images/picoctf_2022/rps.png)

Returning to the `play()` function, we see that the scoring is handled by this part of the function:

```c
if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
} else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
}
```

`player_turn` is whatever the user input during the `tgetinput()` function call. `computer_turn` is a randomised integer from 0 to 2 inclusive, and `loses` is the array ['paper', 'scissors', 'rock']. `loses[computer_turn]` stores the player's choice which will beat the computer's (code ommitted).

`play()` returns true if `strstr(player_turn, loses[computer_turn])` returns true. `strstr()` returns a pointer to the first occurence of `loses[computer_turn]` in `player_turn`, and a null pointer otherwise. To prevent the null pointer from being returned, we just have to ensure that `loses[computer_turn]` is always found in `player_turn`, and since the program doesn't validate the player's input, we can simply play 'rock paper scissors' to ensure that no matter what `loses[computer_turn]` is it will always be found in `player_turn`, which guarantees us a win.

![Input for guaranteed win](/images/picoctf_2022/rps_guaranteed_win.png)

Thus, we can just repeat this 5 times and this will yield the flag.

This was fun :-)

### SQLiLite (300)

I noticed that even though the login attempt fails, the webpage shows the exact SQL query made given the input username and password. For example, if I enter `foo` as the username as `bar` as the password and try to login, I can see that the SQL query made at the backend is:

```sql
SELECT * FROM users WHERE name='foo' AND password='bar'
```

With this in mind and knowing that we want to login as `admin` (from the hint), I performed an SQL injection by entering `admin';` as the username (it doesn't matter what the password is; I just left it blank). This works because even though the complete compiled query is:

```sql
SQL query: SELECT * FROM users WHERE name='admin';' AND password=''
```

the syntax of sql makes it such that the entire part of the query after the semicolon is ignored, i.e., password verification is bypassed.

Once logged in, the flag can easily be found by inspecting the sourcecode of the page.

---

## Reverse Engineering

### file-run1 (100)

We just need to use `chmod` to change the permissioins (to allow execution). Executing the file then gives the flag.

### file-run2 (100)

Same as file-run1, except we add a command line argument when running the executable.

### GDB Test Drive (100)

Following the instructions suffice. The instructions guide us to display the program in assembly layout, add a breakpoint, execute up to that breakpoint, then jump to another point in the code.

### patchme.py (100)

If we look at the python code, we find that the program asks the user for a password for the flag and checks whether the password is correct before the flag is decrypted. From the code, we can see the password the progran expects, and hence we can reconstruct the password and enter it into the program when asked.

### Safe Opener (100)

If we analyse the java file, we see that the user is first asked to enter a password. The input then undergoes base64 encoding, and the encoded input is then checked against an expected string for a match. The safe is only opened when the base64 encoded input matches the expected string. Therefore we can simply base64 decode the expected string to get the expected password.

### unpackme.py (100)

The python program asks for a password from the user. The source code is:

```python
import base64
from cryptography.fernet import Fernet

payload = b'gAAAAABkzWGO_8MlYpNM0n0o718LL-w9m3rzXvCMRFghMRl6CSZwRD5DJOvN_jc8TFHmHmfiI8HWSu49MyoYKvb5mOGm_Jn4kkhC5fuRiGgmwEpxjh0z72dpi6TaPO2TorksAd2bNLemfTaYPf9qiTn_z9mvCQYV9cFKK9m1SqCSr4qDwHXgkQpm7IJAmtEJqyVUfteFLszyxv5-KXJin5BWf9aDPIskp4AztjsBH1_q9e5FIwIq48H7AaHmR8bdvjcW_ZrvhAIOInm1oM-8DjamKvhh7u3-lA=='

key_str = 'correctstaplecorrectstaplecorrec'
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)
plain = f.decrypt(payload)
exec(plain.decode())
```

If we look at the code, one thing that might stand out is the lack of any explicit code which asks the user to enter a password despite the fact that the program does so when it is executed. However, the last line of the code uses `exec()`, which executes a dynamically created program. We can guess that the part of the code which asks for and checks user input is accounted for by `plain.decode()` and executed by `exec()`.

To peek at the code which handles asks and handles user input, we can simply look at the result of `plain.decode()`, and we can do this by inserting the line `print(plain.decode())` above the last line of code. This prints the code which handles user input and validation, and more importantly reveals the flag for the level.

### Fresh Java (200)

I installed [Ghidra](https://github.com/NationalSecurityAgency/ghidra) on a VM running Kali and decompiled the Java class file provided. From the decompiled main function we can see that the program asks the user to enter a key, then performs a few checks on the input. The program first checks if the entered key is 34 characters long. Then the program checks each of these 34 characters (from back to front) to see if they match a specific ASCII character. If any of these checks fail then 'invalid key' is printed, else 'valid key' is printed.

Therefore, if by looking through each of these checks we are able to reconstruct the key deeemed valid by the program, which is the flag for this challenge.

### bloat.py (200)

Same as before, the python program asks for a password for the flag. The source code is, however, heavily obfuscated. To get the unobfuscated expected password we can simply launch a python session in the console, define array `a` just like in `bloat.py`, then call `print()` on the long series of concatenated `a` references arg432 is checked against. We can then run `bloat.py` with this expected password and get the unencrypted flag.

### Bbbbloat (300)

If we execute the downloaded file, we see that it asks the user 'What's my favorite number?'.

I imported the executable into Ghidra, and saw that there was no clearly labelled main function. I used the program text search function to search for the word 'number', and identified a function which resembled the main function. I renamed this function 'main'. The relevant bit in ghidra's decompiled main function is:

```c
undefined8 main(void)

{
  /*
  ...
  variable instantiation and assignment ommitted
  ...
  */

  printf("What\'s my favorite number? ");
  local_44 = 0xd2c49;
  __isoc99_scanf(&DAT_00102020,&local_48); // A
  local_44 = 0xd2c49;
  if (local_48 == 0x86187) { // B
    local_44 = 0xd2c49;
    local_40 = (char *)FUN_00101249(0,&local_38);
    fputs(local_40,stdout);
    putchar(10);
    free(local_40);
  }
  else {
    puts("Sorry, that\'s not it!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

My guess is that line A scans the stdin for the user's input after the program asks them for it, and stores it in `local_48`. `local_48` is then compared against 0x86187 in line B. Since the 'else' clause (when `local_48` != 0x86187) indicates that the input is wrong, my guess is that the correct favourite number is 0x86187, which is 549255 in decimal. Rerunning the program and entering this number yields the flag.

### unpackme (300)

When executed, the downloaded program asks the user 'what's my favourite number?' and then waits for and evaluates the response.

The downloaded binary is an executable packed with UPX - it is essentially a compressed program which is decompressed at runtime. There are a few ways which we can tell the executable is UPX packed, such as inspecting the strings in the executable or loading the program into a debugger and [looking for a specific pattern of instructions](https://reverseengineering.stackexchange.com/questions/168/how-to-check-if-an-elf-file-is-upx-packed). In our case we know that it is UPX packed because when we load the program into a decompiler there is a string which tells us (and also because it is hinted at in the problem statement).

There are fantastic guides such as [this](https://tech-zealots.com/reverse-engineering/dissecting-manual-unpacking-of-a-upx-packed-file/) and [this](https://infosecwriteups.com/how-to-unpack-upx-packed-malware-with-a-single-breakpoint-4d3a23e21332) which detail how to manually unpack a UPX packed executable, but I decided to use the command `upx -d unpackme-upx` to unpack it automatically.

We can load up the unpacked executable into a decompiler / reverse engineering tool like Ghidra. If we navigate to the `main` function, we can see that in line 21 'What's my favorite number?' is printed. In line 22, `__isoc99_scanf` (presumably) scans the user input from stdin and stores the value in `local_44`. Most importantly, in line 23 the value in `local_44` is compared with 0xb83cb (754635 in decimal) and then executes some code depending on the result of this comaprison.

This indicates that 754635 is the program's favourite nunber. Sure enough, if we enter 754635 when asked by the program, it gives us the flag.

---

## Web Exploitation

### Includes (100)

Digging around the source code of the website we find halves of the password in style.css and script.js.

### Inspect HTML (100)

Flag is in page source.

### Local Authority (100)

Looking at login.php, we can see that the input username and password is pass into a `checkPassword()` function which is defined in secure.js. The function reveals the expected username and password in plaintext, and we can just use these to login to the webpage and retrieve the flag.

### Search source (100)

Simply looking around the various source code files and using ctrl/cmd+f to look for 'picoCTF' is enough to find the flag (can also use htttrack to copy the source code to local machine and use grep).

### Forbidden paths (200)

I used Burpsuite's proxy function to intercept requests made to the webpage. If we type in a valid file name (e.g. oliver-twist.txt), we see that the specified file to read is passed as the `filename` parameter. Since the question specifies that website files like oliver-twist.txt are located in the `/usr/share/nginx/html/` folder, my guess for what happens at the backend is that `read.php` retrieves the desired file from the `filename` request parameter, then looks in the `/usr/shar/nginx/html/` folder to retrieve the contents of the desired file.

![Intercepted request packet showinf 'filename' parameter](/images/picoctf_2022/forbidden_paths_intercept1.png)

We also know that the flag resides in `/flag.txt`, i.e. a file called `flag.txt` in the root directory. We need to ask `read.php` to look at the root directory instead of the `html` directory. We can do this by using the 'parent directory' specifier '..'. For example, `/foo/bar/..` resolves to just `/foo` since `/bar/..` just means 'parent of `bar`. Following the same logic, if we want to tell `read.php` to look at a specific file in the root directory, all we have to do is tell it to look at the parent directory of the current folder enough times. `/usr/share/nginx/html/..` resolves to 'parent of html folder' i.e. `/usr/share/nginx`, `/usr/share/nginx/html/../..` resolves to 'parent of the parent of the html folder' i.e. `/usr/share` etc.

Therefore, we can just enter `../../../../flag.txt` (note the lack of forward slash at start) in the 'filename' entry box on the homepage, and `read.php` will display the contents of `/usr/share/nginx/html/../../../../flag.txt` i.e. `flag.txt`.

### Power Cookie (200)

I used Burpsuite's proxy function to intercept packet sent when we click on the 'continue as guest' button on the homepage, and found that there is an 'isAdmin' cookie which has value 0. Naturally, I changed the value of the cookie to 1 and forwarded the packet to the server, which immediately caused the flag to be revealed.

![isAdmin cookie](/images/picoctf_2022/power_cookie.png)

### Roboto Sans (200)

The title of this question is a little misleading. I initially thought it was font related because Roboto is a font and the word 'sans' is commonly used when describing or naming fonts. However, I realised that the question was alluding to was the website's robot.txt file, which tells web crawlers belonging to search engines which webpages it is allowed to crawl. The robots.txt contained a few encrypted strings, one of which was base64 encoded. Decoding the base64 string gave me a path to a page containing the flag.

### Secrets (200)

If we inspect the source code of the home page, we see that line 15 references 'secret/assets/index.css'. Therefore I navigated to \<source url\>/secret/ and found a reference in the source code to 'hidden/file.css'. I then visited \<source url\>/secret/hidden/, where I found a reference to 'superhidden/login.css' in the source code. Navigating to \<source url\>/secret/hidden/superhidden/ and looking at the source code yields the flag.

### SQL Direct (200)

If we use `\d` we can see that there is a table called `flags`. Therefore we can simply use `SELECT * FROM flags;` to show all rows in the `flags` tables including the flag for this level.

---

## Forensics

### Enhance! (100)

The downloaded image is an svg file, which can be opened in any web browser. The image appears to just be a large black circle with a small white circle in it's centre. Upon inspecting the source file we find the flag, which has been fragmented into a few parts (remove the spaces in between the characters).

### Lookey here (100)

We can simply use `grep` with `cat` to look for the password (which has the prefix 'picoCTF').

### Packets Primer (100)

We download the pcap file and open it with wireshark. The flag is in one of the entries in the capture (the client making a push request to the server).

### Redaction gone wrong (100)

We can simply copy all the text from the pdf and paste it somewhere else. This distinguishes between the intentional and accidental redaction and also reveals the flag.

### Sleuthkit intro (100)

The downloaded file is a .gz file so first we have to use `gunzip` to extract the disk image. Running `mmls disk.img` shows that the linux partition has a particular length. That length is the expected answer in the access checker program, which gives the flag when the length is submitted.

### Sleuthkit Apprentice (200)

The downloaded file is a .gz file so we have to first use `gunzip` to extract the disk image. I opened the image file in Autopsy to analyse the image. I tried using the keyword search feature to look for strings beginning with 'picoCTF', but there were no results, so I had to manually look for the flag. There were 2 partitions which possibly contained the flag so I just browsed through each of these. I found a file called 'flag.uni.txt' in root > my_folder, which contained the picoCTF flag. The characters in the flag were separated by some delimitter, like p.i.c.o.C.T.F..., which was why the keyword search didn't work.

### Operation Oni (300)

I unzipped the .gz file and threw the disk image into autopsy. There were two partitions to dig through, and since I was looking for an ssh key, I looked at the .ssh folder under the root folder and found the private key. I copied the key into a new file in my local system and used ssh to connect to the remote host and found the flag.

### Eavesdrop (300)

If we open up the packet capture in wireshark, we can actually inspect the contents in each packet to figure out what is going on. We can actually look at the (unencrypted) contents of each packet by selecting the data field in the packet details pane and looking at the packet bytes pane:

![Example of looking at data field to discover contents od packet.](/images/picoctf_2022/eavesdrop_data_field.png)

The contents of this capture seems like a conversation between 2 users with 2 different IP addresses on an instant messaging platform. The [PSH, ACK] packet (e.g. packet 12 above) seems to represent a message being sent to a particular recipient, and the following [ACK] packet (packet 13 above) is probably an acknowledgemet that the destination received the message.

The messages are interspersed with various auxillary requests like DHCP and ARP which are not as important as the TCP packets for the purposes of this investigation. The following is a summary of the conversation between A (10.0.2.4) and B (10.0.2.15) in the capture:

- [12-17] A asks B how to decrypt the file
- [18-25] B tells A how to decrypt the file and A acknowledges
- [26-31] B tells A they should use Discord in the future because it is more secure
- [32-37] A asks B to transfer the file again
- [48-53] B confirms with A that the transfer is on port 9002
- [54-58] B sends A the file
- [59-73] B confirms that they have sent the file and A acknowledges receipt

Packet 57 supposedly contains the file which B sends to A. The raw hexadecimal bytes in the data field is:

```
53616c7465645f5f3c4b26e8b8f91e2c4af8031cfaf5f8f16fd40c25d40314e6497b39375808aba186f48da42eefa895
```

Packet 18 contains the instructions for decrypting the file which B sends to A upon request. The instructions are:

```
openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
```

My guess is that 'file.des3' is the file that A and B were referring to, and is what was sent by B to A in packet 57. Therefore, I exported the contents of the data field of packet 57 as 'file.des3' (right-click on packet 57 > export packet bytes ) and ran the decryption command in the console. This created a new file called 'file.txt' containing the flag.

Fun level :-)

### Operation Orchid

After running `gunzip` on the downlaoded file, I uploaded the extracted `.img` in Autopsy. In the root folder located in the third partition, there are 3 files which caught my attention: .ash_history, flag.txt (deleted), and flag.txt.enc.

.ash_history seems to be a log of some commands which the previous user has ran. From the log, we can see that the user created the `flag.txt` file, edited it's contents using nano, and created an encrypted copy of it called `flag.txt.enc` using opensssl with aes256 encryption. They then used `shred` to write over `flag.txt` (plaintext) with random bits so it becomes unretrievable.

Since we had the encrypted file and we know how the user encrypted the file, we can just reverse this encryption to retrieve the contents of the original file. To do this, we first export `flag.txt.enc`. Since we know that the original file was encrypted using the command `openssl aes256 -salt -in flag.txt -out flag.txt.enc -k unbreakablepassword1234567`, we can simply reverse the encoding using

```bash
openssl aes256 -salt -d -in flag.txt.enc -out flag.txt -k unbreakablepassword1234567
```

which gives us a new file called `flag.txt` which contains the flag.

---

## Cryptography

### basic-mod1 (100)

I wrote a script to help me with the translation:

```python
translation = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
encoded = "165 248 94 346 299 73 198 221 313 137 205 87 336 110 186 69 223 213 216 216 177 138 "
encoded = encoded.strip().split(" ")
answer = ""
for n in encoded:
    a = int(n) % 37
    answer += translation[a]
print(answer)
```

### credstuff (100)

'cultiris' was the 378th username, and we find that the 378th password was 'cvpbPGS{P7e1S_54I35_71Z3}'. Throwing this into Cyberchef with a ROT13 recipe we get the flag.

### morse-code (100)

I used [this online morse audio decoder](https://databorder.com/transfer/morse-sound-receiver/).

### rail-fence (100)

I threw the string into cyberchef and used the built in rail fence cipher decoder.

### substitution0 (100)

I threw the encrypted string into cyberchef and defined the substitution recipe with the key at the beginning as the plaintext and the regular alphabet as the ciphertext. This undoes the substitution and we are able to retrieve the flag.

### substitution1 (100)

I used [this online tool](https://www.dcode.fr/substitution-cipher) to help with the decoding process. I noticed that the last string in the paragraph was the flag, which began with 'picoctf'. Therefore, I populated the decoding table with the following:

| plaintext | ciphertext |
| --------- | ---------- |
| ...       | ...        |
| c         | s          |
| ...       | ...        |
| f         | t          |
| ...       | ...        |
| i         | z          |
| ...       | ...        |
| o         | k          |
| p         | b          |
| ...       | ...        |
| t         | y          |
| ...       | ...        |

I then noticed that the first word in the passge was 'CTFe'. Since we know that 'CTF' is the correct plaintext (from using the clue from the flag), I guessed that 'CTFe' was actually 'CTFs'. Therefore, I added the mapping s - e.

The string in parantheses immediately following 'CTFs' becomes '(SAODT FOD CJPTNDR TAR FHJM)'. Since we know that the letters p, i, c, o, t, f, and s are decoded, I made an intelligent guess that the string in the parantheses was 'short for capture the flag'. This means that we can update the substitution table, which looks like the following at this stage:

| plaintext | ciphertext |
| --------- | ---------- |
| a         | j          |
| ...       | ...        |
| c         | s          |
| ...       | ...        |
| e         | r          |
| f         | t          |
| g         | m          |
| h         | a          |
| i         | z          |
| ...       | ...        |
| l         | h          |
| ...       | ...        |
| o         | k          |
| p         | b          |
| ...       | ...        |
| r         | d          |
| s         | e          |
| t         | y          |
| u         | n          |
| ...       | ...        |

The message is now pretty decoded. I then proceeded to fill up the rest of the unmapped characters by analysing the almost decoded words. The final substitution table is:

| plaintext | ciphertext |
| --------- | ---------- |
| a         | j          |
| b         | l          |
| c         | s          |
| d         | q          |
| e         | r          |
| f         | t          |
| g         | m          |
| h         | a          |
| i         | z          |
| ...       | ...        |
| k         | v          |
| l         | h          |
| m         | x          |
| o         | k          |
| p         | b          |
| q         | u          |
| r         | d          |
| s         | e          |
| t         | y          |
| u         | n          |
| v         | w          |
| w         | g          |
| ...       | ...        |
| y         | o          |
| ...       | ...        |


### Vigenere (100)

I simply used cyberchef's vigenere decode with the specified key and managed to retrieve the flag.


