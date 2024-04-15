+++
title = 'PicoCTF 2024'
date = 2024-03-17
draft = true
tags = ['coding', 'ctf', 'cybersecurity', 'picoCTF', '2024']
math = true
+++

## Web Exploitation

### Bookmarklet (50)

Create a new bookmark in the browser and enter the provided javascript code in the 'url' parameter. Clicking on the added bookmark runs the javascript code and decrypts the encrypted flag.

### WebDecode (50)

Navigating to the 'About' page and viewing the source code for the page (right click, view page source), we find a long encoded string in the html code which seems interesting:

```html
...
</header>
  <section class="about" notify_true="cGljb0NURnt3ZWJfc3VjYzNzc2Z1bGx5X2QzYzBkZWRfMDJjZGNiNTl9">
   <h1>
    Try inspecting the page!! You might find it there
...
```

Throwing the string into cyberchef and using base64 decode, we find the flag.

### IntroToBurp (100)

If we use the 'proxy' feature in burpsuite to intercept requests the website sends out, we see that there is a session cookie attached to the request.

![session cookie in request](/images/picoctf-2024/introtoburp-session-cookie.png)

If we use a [tool](https://www.kirsle.net/wizards/flask-session.cgi) to decode the cookie value, we can see the OTP expected by the server.

![decoded cookie](/images/picoctf-2024/introtoburp-decoded.png)

We can then simply change the otp value in the request body to the expected otp before forwarding the request to the server.

The hints in this question are a little but misleading because mangling the request (like one would do to probe for an sql injection etc.) does nothing to help.

### Unminify (100)

I don't really know what the point of this challenge is because the flag can be found just by looking at the page source and scrolling through the code.

### Trickster (300) (post-contest)

The site is apparently a PNG processing app. Users can upload PNG files to the site.

We can begin by doing some simple testing. If we upload a legitimate PNG file to the server, we see that the site says

> 'File uploaded successfully and is a valid PNG file. We shall process it and get back to you... Hopefully'

additionally, there is also no link to where the uploaded PNG is stored on the server.

If we try to upload a non-png file, such as a text or jpeg file, the website will reject the file and prompt us saying that 'the filename does not contain .png'.

If we try to add .png to the name of a non-png file, we get a message saying that the file is not a valid PNG image followed by a string of hexadecimal characters. If we decode that string of characters, we find that it corresponds to the first 4 characters of whatever file had been uploaded.

This indicates that the site is also checking the first 4 characters of the file to verify whether or not it is a PNG. This alludes to the idea of magic bytes/numbers or [file signatures](https://en.wikipedia.org/wiki/File_format#Magic_number). Briefly speaking, magic bytes indicate to the computer what kind of file it is and every type of file, such as .png, .jpeg, .txt etc [have their own signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

Something we can do to exploit file upload systems is to upload a web/reverse shell to gain access to the web server. A webshell is essentially a (php) script which, when uploaded to the server, establishes a connection between the local machine and the web server for us to run shell commands on the web server.

From our initial testing, we know that the php webshell file we are going to upload needs to have the following:

1. needs to have '.png' in its name.
2. needs to have the PNG magic bytes at the beginning.

I tried a few different webshells but the only one which worked for me was [this](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/web/simple_php_web_shell_post.php)HTTP-POST based one. To use it, we first save the script locally as `payload.png.php`. The use of '.php' after '.png' in the filename is so that the web server recognises and runs the file as a php script, while at the same time satisfying requirement 1 above.

To satisfy requirement 2, we can either open up a hex editor and insert the necessary magic bytes for PNG files (89 50 4E 47) right at the start of the file, or simply open the file and type '#PNG' right at the start ('#' doesn't correspond to 0x50 but this doesn't seem to matter; # is also how comments are indicated in PHP).

With the payload prepared, all we have to do is to upload it to the site. If the file doesn't show up or cannot be selected during the file selection process, make sure to change the filters or options limiting the type of file to just PNG (because the payload is ultimately a PHP file).

Once it has been successfully uploaded, we need to locate it on the server and access it to access the webshell. It turns out that the file is located in the `uploads` subdirectory, i.e. the url of the payload is `<domain: port number>/uploads/payload.png.php` (this can be discovered either by guessing, running a program like dirb or dirbuster to enumerate the site, or stumbling upon and reading `robots.txt`, which makes a reference to `uploads`).

If we navigate to the payload, we should see the following:

![simple webshell deployed](/images/picoctf-2024/trickster-webshell.png)

We can now execute all sorts of shell commands by entering them into the box and hitting enter; the output of these commands will be printed onto the webpage.

One thing to note is that the working directory resets to `/var/www/html/uploads` after every round of commands is run. For example, if we type `cd ..`, hit enter, type `pwd`, then hit enter again, the output will be `/var/www/html/uploads`, just like the `cd ..` command was never ran.

To get around this we can chain multiple commands using ';' as the delimiter and execute all of them at one go. For example, if we type `cd /var; ls; pwd` the contents of `/var` and `/var` will be printed. Alternatively, we can just append the target directory to whatever command we want to run. For example, to look at the contents of `/var/www/html`, we can just use `ls /var/www/html` instead of changing directory and then executing `ls`.

If we do a bit of digging around, we will eventually discover an interesting text file in `/var/www/html` which contains the flag we are looking for (the file _isn't_ called 'flag').

## Cryptography

### Interencdec (50)

The downloaded file contains a string ending with '==', which indicates that it is probably base64 encoded. Using cyberchef to base64 decode the string, we get another base64 encoded string. Ater base64 decoding the string (in between the parantheses) again, we get a string resembling a flag, but a little scrambled: 'wpjvJAM{jhlzhy_k3jy9wa3k_i204hkj6}'. We can first try to decode this by assuming its encrypted using a Caesar cipher – a rather common encryption scheme. Using the cyberchef ROT13 brute force operation with 'picoCTF' as the crib (known plaintext string), we are able to retrieve the decrypted flag.

### Custom encryption (100)

If we open the file containing the encoded flag, we see the ciipher text in addition to values of variables a and b.

This is a high-level breakdown of the encryption algorithm used to derive the ciphertext in enc_flag:

```pseudocode
plain_text <- text_to_encrypt
text_key <- 'trudeau'
p <- 97
g <- 31
a <- 94
b <- 29
u <- 43 = generator(31, 94, 97)
v <- 11 = generator(31, 29, 97)
key <- 93 = generator(11, 94, 97)
b_key <- 93 = generator(43, 29, 97)
shared_key <- 93
semi_cipher <- dynamic_xor_encrypt(text_to_encrypt, 'trudeau') # alpha
cipher <- encrypt(semi_cipher, 93) # beta
return cipher
```

The `dynamic_xor_encrypt` function at alpha essentially xors each character of the plaintext (from back to front) with the string `trudeau` (with wraparound to account for differences in length).

The `encrypt` function at point beta creates an array where each element in the array is the product of the ascii value of the character in the corresponding position in the same index with 311 and 93.

With all this information, we can then create the following script to reverse the encryption:

```python
def generator(g, x, p):
    return pow(g, x) % p

def reverse_encryption(ciphertext_array, shared_key):
    decoded = ""
    for c in ciphertext_array:
        decoded += chr(int((c / 311) / shared_key))
    return decoded

def dynamic_xor_decrypt(ciphertext, text_key):
    cipher_text = ""
    key_length = len(text_key)
    for i, char in enumerate(ciphertext):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return cipher_text[::-1]

# hardcoded values from the source code and the enc_flag file
ciphertext_array = <value from enc_flag>
text_key = "trudeau"
a = 94
b = 29
p = 97
g = 31

u = generator(g, a, p)
v = generator(g, b, p)
key = generator(v, a, p)
b_key = generator(u, b, p)

if key == b_key:
    shared_key = key
else:
    print("Invalid key")
    exit()

semi_cipher = reverse_encryption(ciphertext_array, shared_key)
plaintext = dynamic_xor_decrypt(semi_cipher, text_key)
print(plaintext)
```

The code should be quite simple to parse. The `encrypt` function in the original encryption code can be reversed by changing multiplication to division and using `chr()` to cast the integer values back to ascii characters. The `xor` function can be reversed by just running the same xor function but from front to back and then reversing the output once the loop finishes. This works because one property of XOR is A xor B xor B = A, which means that semi_cipher xor text_key = plaintext since semi_cipher = plaintext xor text_key.

Running the code gives us the flag.

### C3 (200)

We are provided with a file called `convert.py` which is supposedly the encoder and the ciphertext. We can begin by trying to write a script to reverse `convert.py` which we will call `decoder.py` :

```python
encoded = <ciphertext>
lookup1 = "\n \"#()*+/1:=[]abcdefghijklmnopqrstuvwxyz"
lookup2 = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst"
decoded = ""
prev = 0
for char in encoded:
    lookup2_index = lookup2.find(char)
    cur = (lookup2_index + prev) % 40 # alpha
    decoded += lookup1[cur]
    prev = cur
print(decoded)
```

To reverse the conversion, for each character in the ciphertext, we need to first find its index in lookup2, then use that index along with the value of `prev` to find `cur`, the index of the character in lookup1 which belongs in the plaintext. The calculation of cur in line alpha is such because from the original converter, (cur - prev) % 40 = lookup2_index. If we consider all 3 cases for values of (cur - prev), i.e. = 0, < 0 or > 0, along with the maximum possible values for current and prev, we realise that the calculation for cur is the same in all 3 cases.

If we run `decoder.py`, we get the following output, which seems to be a python2 script (let us call this `encoder.py`):

```python
#asciiorder
#fortychars
#selfinput
#pythontwo

chars = ""
from fileinput import input
for line in input():
    chars += line
b = 1 / 1

for i in range(len(chars)):
    if i == b * b * b:
        print chars[i] #prints
        b += 1 / 1
```

At this point, I had no idea how this script related to the original problem. After doing some random testing, I just Googled the first 4 lines of the script (#asciiorder #fortychars...) and came across [this webpage](https://onecompiler.com/python2/4273qrk9w). The user who used the online compiler essentially fed `encoder.py` into itself as input to be encrypted. The output was the string 'adlibs'. Out of ideas, I tried enclosing it with the wrapper and submitting that as the flag and I was shocked that it got accepted!

To be honest, if I hadn't found that online code compiler I probably wouldn't have been able to solve this. I don't know if I'd have tried feeding `encoder.py` into itself as input, or be able to figure out that the short string 'adlibs' was the intended flag. Perhaps the comment 'selfinput' was meant to hint to the former fact, but I don't think it was obvious enough to me, and judging by the extremely poor ratings on the pico platform, I think most people agree.

## Reverse Engineering

### Packer (100)

The program asks for a password to unlock the file. Running the `strings` command, we see the string 'UPX!', which indicates that this executable was probably packed with [UPX](https://upx.github.io/).

Unpacking it is as simple as running the command `upx -d <filename>` (assuming the upx command line tool is installed). Running `strings` again once the file is unpacked yields more indicative strings. One of the strings include the flag provided if the user enters the correct input. Analysing the string, we can tell that its probably in hex format since each character is a numeral or character from a to f inclusive. Sure enough, if we convert that string from hex to ascii, we get the plaintext flag.

### FactCheck (200)

The program strangely doesn't do anything when ran, but when we run strings, we can see half the flag.

## Forensics

### Scan Surprise (50)

Retrieving the flag involves simply scanning the qr code (I used [an online scanner](https://scanqr.org/)).

### Verify (50)

The provided resources include a folder of many files, a text file containing the sha256 hash of the target file, and a shell script to decrypt the file.

We have to first identify the target file in the files folder. We can do this by generating the sha256 hashes for all files in the folder then using `grep` to find the one which matches the target. When in the `files` folder, we simply run:

```bash
shasum -a 256 | grep <target hash>
```

Once we have identified the target file to decrypt, we can proceed to use `decrypt.sh` to decrypt it. I had to make some modifications to get the script to work as the script presumes the location of which the files are stored on the system. Once that is done, the target file is then successfully decoded and the flag is retrieved.

### CanYouSee (100)

The hint suggests that we need to view the information about the image. The information about any image is its metadata, and we can use the command line to extract the metdata of the image using `exiftool <filename>`. We notice that the 'attirubution URL' has a base64 encoded value, and decoding this value gives us the flag.

### Secret of the polyglot (100)

After downloading the file, we see that it seems to contain only the second half of the flag. It seems like the file is a pdf, but if we look at the hex data of the file by performing a hex dump (for example, by opening it in hex fiend), we see that the file starts with '.PNG'. If we change the extension of the file from '.pdf' to '.png', we immmediately get the first half of the flag.

### Endianness-v2 (300)

Running the `strings` command on the file seems to yield nothing but gibberish. If we open the file in a hex viewer like hex fiend, we don't find anything obvious too.

Following the clue in the question of the title, we can copy the file's hexadecimal data and use cyberchef's 'swap endianness' feature to see if it gets us anywhere. We see the following:

![output of swap endianness feature](/images/picoctf-2024/endianness-v2-cyberchef.png)

The string 'JFIF' is in the first few bytes of the output, and if we Google that string we find that it indicates that the file is a jpeg file. Following this lead, we can then click on the 'save output to file' button in cyberchef to save the converted data as a jpg file, and upon opening that jpg, we find the flag.

## General Skills

### Super SSH (25)

Connect using `ssh ctf-player@titan.picoctf.net -p 65080` and enter the password when prompted.

### Commitment Issues (50)

Unzipping the donwloaded file, we get a text file called `message.txt` containing the string 'TOP SECRET'.

Going with the hint in the title of the challenge, we can check the commit history using the command `git log`. We see that there was one earlier commit with the comment 'create flag'.

This indicates that if we were able to revert to that commit, we should be able to see the unredacted flag. We do this by taking note of the commit id in the commit history, then use the command `git checkout <commit id>`.

If we go back to `message.txt`, we find that it now contains the flag.

### Time machine (50)

Using a terminal and after changing the working directory to the downloaded folder, we just need to use `git log` to see the commit history, read the commit messages, and hence find the flag.

### Blame Game (75)

To find the exact changes in the file and the users who made those changes, we can use the following: `git log --follow message.py`.

### Collaborative Development (75)

Running `git branch -a` in the downloaded directory, we see that there are 3 branches in addition to main: feature/part-1, 2, 3.

The feature/part-1 branch can be merged into main without problem using `git merge feature/part-1`. However, when we try to repeat the same with part-2, we are told that there are merge conflicts we need to fix. We can use vim to remove the extra lines in `flag.py` which cause the conflicts, commit the changes, then retry the merge.

When we try to merge part-3, the same problem occurs. The same solution for part-2 should work to resolve this, but we don't actually need to do it - we can just resolve the merge conflict indicators in `flag.py` then run `python flag.py` to generate the flag.

### Binhexa (100)

This challenge presents a series of randomised question we need to answer. Some binary operations such as bitwise and and or are easy to manually carry out, but python can also be used to help the process. To indicate to the python interpreter that numbers are in binary, prefix the binary string with 0b. For example, a = 0b101 tells python that '101' is supposed to be interpreted as binary. The function `bin(num)` and `hex(num) `is also useful to convert a base-10 integer into binary or hex format. Completing all the questions yield the flag.

### Binary search (100)

This can be solved pretty straightforwardly by taking a binary search approach. The guesses need to be accurate or else there won't be enough chances.

### Endianness (200)

Since the source code contained functions for deducing the correct answers from the randomly generated string, we can actually use those functions to help us write a program `solution` to give the little and big endian format for a given input string:

```c
# inclusions and find_little_endian() and find_big_endian() same as the source code

...

int main()
{
    printf("enter the word to convert: ");
    fflush(stdout);

    char word[6];
    scanf("%s", word);

    char* little_endian_answer = find_little_endian(word);
    char* big_endian_answer = find_big_endian(word);

    printf("little endian: %s\n", little_endian_answer);
    printf("big endian: %s\n", big_endian_answer);

    exit(0);
    return 0;
}
```

To find the flag, we can just launch both the application and `solution`, take the randomly generated string from the application and put it into `solution` to generate the little and big endian answers and input those into the application.

I wrote `solution` instead of working through the solution manually because I wasn't clear about how to solve it, but after using `solution` I kind of understand how to do it manually:

Suppose we have the string 'adtlw'. First, we have to convert each character to their ascii representation:

a $\rightarrow$ 0x61
d $\rightarrow$ 0x64
t $\rightarrow$ 0x74
l $\rightarrow$ 0x6c
w $\rightarrow$ 0x77

'Big-endian' means the biggest byte (leftmost byte) is stored first (in lower memory addresses) while 'little-endian' means the smallest byte (rightmost byte) is stored first ([additional reference](https://www.spiceworks.com/tech/tech-general/articles/big-endian-vs-little-endian/)). Since 0x61 ('a') is the biggest byte (contains the most significant bit in the word), in big-endian representation it is stored first with everything else following. Similarly, since 0x77 ('w') is the smallest byte (contains the least significant bit in the word), it is stored first in little-endian representation.

Therefore, the little and big representations for 'adtlw' are '776c746461' and '6164746c77' respectively.

### Dont-you-love-banners (300)

The application asks for a password. The clue states that the server has been leaking information, which indicates that the password could be found there. If we run an nmap scan on the server using `nmap -sC -sV <ip> -p <port>`, we find an interesting string in the SSH fingerprint strings: 'My*Passw@rd*@1234'.

It turns out that this is the password the application is looking for. Once the password is entered in, the application asks a few questions which can be served by just doing a Google search and performing some guesses, such as 'What is the top cyber security conference in the world?' and 'the first hacker ever was known for phreaking(making free phone calls), who was it?'.

Once these questions are answered correctly, we get access to a shell. The task now is to find the file containing the flag. The problem statement says that the file is in the `/root` directory. A file called `flag.txt` is indeed there, but can only be read by root, whereas we are using the shell as 'player'.

The `/root` directory also contains another file, `script.py`, which seems to be the script used to serve the player the banner and the questions when the player first connects to the application. The interesting thing about this script is that to serve the banner, the script opens and reads from `/home/player/banner` before printing its contents to the console. This facat, coupled with the fact that `script.py` is (probably) ran as a root user, means that we might be able to get `script.py` to print out the contents of `flag.txt` if we are able to change `/home/player/banner`.

Following the hint provided, one way to get `script.py` to print out the flag is if we modify `/home/player/banner` to become a symlink to `flag.txt`. If this is done, when `script.py` tries to read from `banner` it will be directed to `flag.txt` and read from there, and hopefully print out its contents for us.

To establish the symlink, we need to run `ln /root/flag.txt -s -f` in `/home/player`. The `-s` flag specifies that its a soft link, while the `-f` flag forces the link to be established (because 'banner' already exsist). All that is left to do is to exit the application and make the connection again. The flag should be printed in place of the original challenge banner.

## Binary Exploitation

### Format string 0 (50)

Analysing the source code, we see that the flag is printed when a segmentation fault occurs, and the easiest way to trigger a segmentation fault is entering a large input (larger than allocated buffer size). When prompted to enter Patrick's order, entering a random long string (>> 32 characters long) causes a segmentation fault and prints the flag to the console.

### Heap 0 (50)

Analysing the source code, we see in the `check_win()` function that the flag is printed only if `safe_var` is not the default value 'bico'.

When we run the application, we see that `safe_var` is on top of the user input variable in the heap. Since we are able to see the memory addresses of both `safe_var` and `user_input`, we are able to caculate the difference to find the size of `user_input`. In my case, the variables differed by 32 bytes. This meant that if I appended a string to 32 random characters, and wrote that as user input, then that string should overflow such that that appended string will become the new value of `safe_var`.

![Heap before](/images/picoctf-2024/heap-0-before.png)

I generated a random 32 character long string using an [online buffer overflow pattern generator](https://zerosum0x0.blogspot.com/2016/11/overflow-exploit-pattern-generator.html) and appended a string at the end of it. Sure enough, after writing that to buffer, I observed that the value of `safe_var` has changed to the value of that appended string, and I am now able to retrieve the flag.

![Heap after](/images/picoctf-2024/heap-0-after.png)

### Format string 1 (100)

### Heap 1 (100)

This challenge is similar to the heap 0 challenge, except that the flag is revealed if we change `safe_var` from the default value of 'bico' to 'pico'.

To achieve this, we can write the following string to the buffer to cause a buffer overflow: [a: some number of random characters] + [b: pico]. a will be stored in the `input_data` variable, but will be so long such that a heap buffer overflow occurs and b and only b gets stored in `safe_var`, triggering the reveal of the flag.

To do this, we can use a buffer overflow payload generator like [this one](https://zerosum0x0.blogspot.com/2016/11/overflow-exploit-pattern-generator.html) to generate a payload and calculate the exact length section a should be. Suppose we generate a payload 50 characters long, and write it into the buffer. By looking at the last characters of `input_data` stored on the heap, we are able to use the generator tool to deduce the exact length a needs to be:

![State of heap after writing to buffer](/images/picoctf-2024/heap-1-calculating.png)

For example, in the screenshot above we can see that after writing the long string to the buffer the value stored in `safe_var` is '0Ab1...'. This means that if we replace this and everything past it in the input string with 'pico', 'pico' will be written to `safe_var` like we wish.

Therefore, we can write 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Abpico' to the buffer, which makes `safe_var` have the value 'pico', allowing us to retrieve the flag.

### Heap 3 (200)

The hint asks us to read up about 'use after free' vulnerabilities. A ['use after free'](https://www.ctfrecipes.com/pwn/heap-exploitation/use-after-free) vulnerability exists when memory is allocated but the data at the location is not overwritten when the memory is freed, i.e. when that memory is 'marked as unused' and made available for `malloc` to allocate elsewhere. An attacker could exploit this vulnerability to do many things, such as [accessing unintended data or running arbitrary code](https://cwe.mitre.org/data/definitions/416.html).

If we analyse the source code provided, we see that the `win()` function, which gives the flag, is called when the value of the 'flag' attribute for the object stored at memory location x is equal to 'pico'.

To achieve this, we can exploit a use after free vulnerability. We can tell that this vulnerability exists in the program as the pointer returned from `malloc` in the `init()` function is stored in a variable `x`, which is referenced in other places in the program. In each of these cases, there is no check to see whether `x` has been previously freed using the `free_memory()` function before accessing the data stored at `x`.

Therefore, to store 'pico' in the 'flag' attribute for the object stored at `x`, we can exploit this use after free vulnerability by:

1. free `x` using option 5 in the program
2. tell the program we want to allocate an object of size 35 using option 2
3. enter <30 random characters> + 'pico' as the data for flag

The purpose of point 1 is so the system treats the memory address as available for use, to allow the system to allocate it to us for use and writing to in the latter steps.

Step 2 is where we get the system to allocate us `x` for us to write data into. The choice of size 35 is deliberate as it is the size of the object which was previously stored at `x`:

```c
...
// Create struct
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;
...
```

Asking for a 35 byte chunk of memory will cause the allocator to allocate us the memory address stored in `x` as it is an exact size match [and it had been recently freed](https://www.ctfrecipes.com/pwn/heap-exploitation/use-after-free).

The data in step 3 is structured that way because based on the definition of `object`, the first 30 bytes are used to store other attributes and only the last 5 bytes are used to store data for the `flag` attribute (can also use dynamic testing to verify this using payloads structured for calculating buffer overflow offsets like [this one](https://zerosum0x0.blogspot.com/2016/11/overflow-exploit-pattern-generator.html)).

If this is executed correctly, the value of flag becomes 'pico' which allows retrieval of the flag.

![Successfully overwriting the value of the flag attribute](/images/picoctf-2024/heap-3.png)
