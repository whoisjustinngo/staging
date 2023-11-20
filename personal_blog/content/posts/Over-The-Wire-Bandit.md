+++
title = 'OverTheWire: Bandit'
date = 2023-11-07
draft = false
tags = ['coding', 'ctf', 'cybersecurity']
math = true
+++

## Introduction

This is my writeup for OverTheWire's ['Bandit' wargame](https://overthewire.org/wargames/bandit/). It essentially is a capture the flag (CTF) challenge, where the flag in level Each level is a separate server you need to SSH into. To access the next level, you will have to look for a password in the current level for you to make the SSH connection. At each level there is a problem statement containing information about where the password is located and some useful commands that one might need to use to get to it – the challenge is using the commands effectively to retrieve the password.

Please look at the wargame website for the problem statements. Although I will be writing down the commands I use to retrieve the passwords, this document is not so much a tutorial, but more a journal of sorts to document my thought process and the things I learnt along the way.

For context, I do have some experience using linux commands with the CLI, so not everything is completely foreign to me. I will try my best not to directly Google for answers, and use the `man` page as much as possible when I need to check something. Here goes...

## Levels

- [Start $\rightarrow$ Level 0](#start-level-0)
- [Level 0 $\rightarrow$ Level 1](#level-0-level-1)
- [Level 1 $\rightarrow$ Level 2](#level-1-level-2)
- [Level 2 $\rightarrow$ Level 3](#level-2-level-3)
- [Level 3 $\rightarrow$ Level 4](#level-3-level-4)
- [Level 4 $\rightarrow$ Level 5](#level-4-level-5)
- [Level 5 $\rightarrow$ Level 6](#level-5-level-6)
- [Level 6 $\rightarrow$ Level 7](#level-6-level-7)
- [Level 7 $\rightarrow$ Level 8](#level-7-level-8)
- [Level 8 $\rightarrow$ Level 9](#level-8-level-9)
- [Level 9 $\rightarrow$ Level 10](#level-9-level-10)
- [Level 10 $\rightarrow$ Level 11](#level-10-level-11)
- [Level 11 $\rightarrow$ Level 12](#level-11-level-12)
- [Level 12 $\rightarrow$ Level 13](#level-12-level-13)
- [Level 13 $\rightarrow$ Level 14](#level-13-level-14)
- [Level 14 $\rightarrow$ Level 15](#level-14-level-15)
- [Level 15 $\rightarrow$ Level 16](#level-15-level-16)
- [Level 16 $\rightarrow$ Level 17](#level-16-level-17)
- [Level 17 $\rightarrow$ Level 18](#level-17-level-18)
- [Level 18 $\rightarrow$ Level 19](#level-18-level-19)
- [Level 19 $\rightarrow$ Level 20](#level-19-level-20)
- [Level 20 $\rightarrow$ Level 21](#level-20-level-21)
- [Level 21 $\rightarrow$ Level 22](#level-21-level-22)
- [Level 22 $\rightarrow$ Level 23](#level-22-level-23)
- [Level 23 $\rightarrow$ Level 24](#level-23-level-24)
- [Level 24 $\rightarrow$ Level 25](#level-24-level-25)
- [Level 25 $\rightarrow$ Level 26](#level-25-level-26)
- [Level 26 $\rightarrow$ Level 27](#level-26-level-27)
- [Level 27 $\rightarrow$ Level 28](#level-27-level-28)
- [Level 28 $\rightarrow$ Level 29](#level-28-level-29)
- [Level 29 $\rightarrow$ Level 30](#level-29-level-30)
- [Level 30 $\rightarrow$ Level 31](#level-30-level-31)
- [Level 31 $\rightarrow$ Level 32](#level-31-level-32)
- [Level 32 $\rightarrow$ Level 33](#level-32-level-33)

### <a name="start-level-0"></a> Start $\rightarrow$ Level 0

Simple. Make SSH connection using

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

and enter the given password when requested.

### <a name="level-0-level-1"></a> Level 0 Level 1

Use `cat` to display the contents of the readme file and hence the password. No problem.

### <a name="level-1-level-2"></a> Level 1 $\rightarrow$ Level 2 <a name="l1"></a>

Using `cat -` as before no longer works. Everything that I type just ends up getting echoed.

A quick google search for 'dashed filename' as described shows that we have to specify the fullpath when the file we want has a dashed filename, like so:

```bash
cat ./-
```

It turns out that the '-' character is commonly used to specify stdin and stdout in the context of a bash shell. In fact, its an alias for either /dev/stdin or /dev/stdout (depending on context). Therefore, `cat -` was equivalent to telling the shell to `cat` everything I input in stdin (the command line) and hence everything I typed was just echoed back to me.

### <a name="level-2-level-3"></a> Level 2 $\rightarrow$ Level 3

We can escape the spaces in the filename either with backslash character, or enclosing the filename in quotes, like so:

```bash
cat 'spaces in this filename'
```

### <a name="level-3-level-4"></a> Level 3 $\rightarrow$ Level 4

`cd` into the directory, then use `ls -a` to display the hidden file, and then simply use `cat` to display its contents.

<!-- 2EW7BBsr6aMMoJ2HjW067dm8EgX26xNe -->

### <a name="level-4-level-5"></a> Level 4 $\rightarrow$ Level 5

One of the recommended commands in the problem statement is `file`. From the `man` page for the command, I learnt that the `file` command runs some tests on the specified argument(s) in order to classify it as 'text' (meaming ASCII characters/human readable), 'executable', or 'data'. Hence I ran the command passing in all the files in the directory as the argument, taking care to handle the `-` character in the filenames:

```bash
file ./*
```

I was thus able to quickly find the file which is of type 'ASCII text' and hence the password.

### <a name="level-5-level-6"></a> Level 5 $\rightarrow$ Level 6

The problem clues specify some properties of the file containing the password, but the files to search through are all contained in subdirectories in the `inhere` directory. It would take too much effort to look through them one by one.

I read up on the `find` command as hinted in the problem statement, and realised that you can basically use it to search for files in a directory hierarchy (i.e. look in subdirectories and subdirectories of those etc.) which match a specified criteria. This fits our purposes nicely.

While doing some testing I found that there is only one file under the `inhere` directory which is 1033 bytes; the final command I used is:

```bash
find -size 1033c ! -executable
```

which gives us the name of the file containing the password to the next level. Notice that this only implements 2 of the 3 specified properties - its missing the 'human-readable' property. I couldn't really find any relevant test for it in the `find` command but perhaps we could pipe the output of this `find` command to another `file` command if we had to. In any case since searching for a file based on those two criteria is enough, let us move on.

### <a name="level-6-level-7"></a> Level 6 $\rightarrow$ Level 7

Since the hint is that the file is located somewhere on the server, I `cd`-ed to the root directory and ran a `find` command with tests matching the properties described in the problem statement.

In addition to the name of the file containing the password, the output of the `find` command included many entries indicating that some tests were unsuccessful because permission was denied. Of course in this small sample I could look through line-by-line to find the entry indicating the file I'm looking for, this is simply not possible in bigger sample sizes, and therefore I decided to try to find an efficient way to extract the desired result.

I initially tried to find an option in `find` to ignore entries with 'permission denied', but I thought that it was easier to execute `find` first then use `grep` to look for entries in the output _not_ containing the string 'Permission denied'.

After consulting the `man` page for `grep` and trying many different configurations, I still couldn't get it to work properly with the `-v` option for `grep`. `find ... | grep -v 'Permission denied'` still printed all the permission denied lines to the console.

I then consulted Google, and found out that this is likely happening because `grep` runs on stdout, whereas the 'Permission denied' entries are directed to the stderr stream, which results in the error messages still printing to the console.

One way to deal with this is to redirect the stderr to the stdout before executing `grep`, but I decided to essentially discard all the stderr messages (i.e. the permission denied entries) by redirecting the stderr [(file descriptor 2)](<https://en.wikipedia.org/wiki/Standard_streams#Standard_error_(stderr)>) to `/dev/null`. The redirection causes all the error messages from the `find` command, including the 'Permission denied' ones to be directed to a new file called `/dev/null` where it is immediately discarded.

As such, I used the following command to cleanly output in the console the name of the file containing the password:

```bash
find -type f -group bandit6 -user bandit7 -size 33c 2>/dev/null
```

### <a name="level-7-level-8"></a> Level 7 $\rightarrow$ Level 8

We simply redirect the output of the `cat` command to the `grep` command using `|` to search for the 'millionth' keyword like so:

```bash
cat data.txt | grep 'millionth'
```

### <a name="level-8-level-9"></a> Level 8 $\rightarrow$ Level 9

I took the hint in the problem statement and went to look at the `uniq` command. From reading the description in its `man` page, I found out that the command filters _adjacent_ matching lines in the input, i.e. for each line, it looks at adjacent lines and discards duplicates. This means that the lines in the `data.txt` file had to be sorted, which can be done using the `sort` command.

After sorting, we can then use `uniq` to filter out duplicate strings. Since we are interested in the string which appears only once, simply filtering out duplicated strings wouldn't be enough as we won't know how many times each string appeared in the original file. Therefore, we need to use the `--count` option to display the number of actual occurences of each unique string displayed.

We can then simply redirect the output to a `grep` command to find the string with an indicated count of 1.

Therefore, putting it all together with pipes, I got:

```bash
cat data.txt | sort | uniq --count | grep '1 '
```

### <a name="level-9-level-10"></a> Level 9 $\rightarrow$ Level 10

The `strings` command prints the sequences of human readable lines in the file. I simply used

```bash
strings data.txt | grep '='
```

to get the password.

### <a name="level-10-level-11"></a> Level 10 $\rightarrow$ Level 11

I used

```bash
base64 -d data.txt
```

to decode the `data.txt` file and retrieve the password.

### <a name="level-11-level-12"></a> Level 11 $\rightarrow$ Level 12

I knew that I had to rotate the characters 13 positions in order to decrypt the file. One option was to put it into a rot cipher decoder on the internet, but I want to try to do it in the command line.

The `tr` command looks promising, and with some help from Google I managed to figure out how to specify the character set to use for the translation. The final command I used was:

```bash
cat data.txt | tr [a-z] [n-za-m] | tr [A-Z] [N-ZA-M]
```

`[a-z]` means all lowercase letters from a to z, and this is translated to `[n-za-m]` which represents the lowercase characters rotated 13 positions i.e. a, b, c, d...x, y, z is translated to n, m, o, p, ..., k, l, m.

### <a name="level-12-level-13"></a> Level 12 $\rightarrow$ Level 13

I performed the `mkdir` and `cp` process detailed in the problem statement, and I used `xxd -r data.txt` to reconstruct the file from the hexdump, but I still got gibberish.

I spotted the string `data2.bin` in the hexdump data, so I thought that the reconstructed file ought to be that name and hence I specified the output file of the `xxd -r` command to be `data2.bin`. However, after executing `cat` on it I still got gibberish.

However, I ran `file` on the reconstructed `data2.bin` file and I realised its file type was 'gzip compressed data'. This was when I used `mv` to rename `data2.bin` to `data2.gz` and then ran `gunzip data2.gz` to unzip the file.

This replaced `data2.gz` with a new file, `data2`, which I found is of 'bzip2 compressed data' using the `file` command. I repeated the same steps above, first using `mv` to rename `data2` to `data2.bz2`, and then used `bunzip2 data2.bz2` to unzip the file.

This replaced `data2.bz2` with a file called `data2` of file type 'gzip compressed data'. I repeated the same process to unzip this file as I did before, and I ended up with the file `data2` of type 'POSIX tar archive', which I renamed to `data2.tar` using `mv`.

I had a little difficulty extracting from this data2 archive, and simply using `tar -x data2.tar` didn't seem to work. After consulting Google, I found that the right option to use is `-xvf`, `v` meaning verbose, `x` indicating extract, and `f` to specify the target file i.e. the file to extract from.

Running `tar -xvf data2.tar` gave me `data5.bin`, another POSIX tar archive. Running `tar -xvf data5.bin` gave me `data6.bin`, a bzip2 compressed file.

At this point I was wondering how many more files I still have to decompress. I did the same renaming and decompressing/extraction process a few more times and I finally got a file which contained ASCII text and the password. Finally.

<!-- wbWdlBxEir4CaE8LaPhauuOo6pwRmrDw -->

### <a name="level-13-level-14"></a> Level 13 $\rightarrow$ Level 14

From the `man` page for `ssh`, we can use the `-i` option to specify the private key for the ssh connection. While in the bandit server, I tried `ssh bandit14@bandit.labs.overthewire.org -p 2220 -i sshkey.private` but it said that the connection was reset.

A quick search yielded that I should use

```bash
ssh bandit14@localhost -p 2220 -i sshkey.private
```

instead. I don't fully understand it yet, but my guess is that because I was already in the bandit server, I had to use `localhost` instead of the host address as connections to the host address within the bandit server are blocked to conserve resources.

<!-- fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq -->

### <a name="level-14-level-15"></a> Level 14 $\rightarrow$ Level 15

It is simple to retrieve the password from the specified location on the server, but I wonder what the problem statement means by 'submitting the password to localhost'. I took this as a sign that getting the password for the next level didn't involve `ssh`.

I saw that one of the commands I might need to solve the level is `telnet`, and upon reading its `man` page I realised that it is used for interactive communication with another host using the telnet protocol. I decided to try

```bash
telnet localhost 30000
```

which opened a telnet prompt in the console. I entered the password obtained earlier and in response I got the password for the next level. Nice.

<!-- jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt -->

I did some reading and found out that telnet was used to provide access to terminals on a remote host, but due to security concerns (because telnet all information in plaintext), SSH is more popular for that purpose now.

### <a name="level-15-level-16"></a> Level 15 $\rightarrow$ Level 16

Following the recommendations of the problem statement, I read the `man` page for `openssl s_client` and established a connection with the target using

```bash
openssl s_client -connect localhost:30001
```

Entering the password for the current level yielded the password for the next level.

<!-- JQttfApK4SeyHwDlI9SXGR50qclOAil1 -->

### <a name="level-16-level-17"></a> Level 16 $\rightarrow$ Level 17

To figure out which ports have a server listening on them, from reading its `man` page I learnt that I had to use `nmap` with the `-p` option to specify the ports I am interested in (31000-32000). Executing `nmap localhost -p 31000-32000` allowed me to identify the open ports between 31000 and 32000.

Next was to identify which of these ports speak ssl and which do not. I managed to get the private key for the next level by simply trying to connect to each of the ports I got from running the previous `nmap` command and checking to see which one works. This was possible because there weren't many ports to try, but I wonder if there's a way to scan to determine whether a port speaks ssl without trying to connect. From what I gathered from a quick search online, there isn't a dedicated command for checking if a server has SSL enabled and the best way is still directly trying to connect via SSL and seeing if it works. Perhaps if there were more ports one could store the interested port numbers in an input file and write a script to automate the process of trying to connect to the various ports, with the return values of a connection attempt indicating whether or not a server listening on a port speaks SSL.

I simply saved the private key obtained in a file on my computer and used `ssh` to connect to the bandit17 server using the `-i` option to specify the name of the file the key is stored in (had to use `chmod` to change permissions of the key file to something more restrictive before using `ssh`).

### <a name="level-17-level-18"></a> Level 17 $\rightarrow$ Level 18

To identify the password we need to compare the old and new password files. To do this I simply executed

```bash
diff passwords.old passwords.new
```

The result showed that line 42 of the old and new password files differ (`42c42`), and also the value of line 42 in the new password file, which is the password for the next level.

<!-- hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg -->

### <a name="level-18-level-19"></a> Level 18 $\rightarrow$ Level 19

I observed that even though I was able to make the `ssh` connection, I would be immediately logged out once the connection was established. I consulted the `man` page of the `ssh` command and I realised that its possible to specify shell commands to execute once the connection is established. Therefore, I used

```bash
ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
```

to print the password for the next level contained in the `readme` file to the console once the `ssh` connection is established before I get logged out. This was a fun challenge.

<!-- awhqfNnAbc1naukrpqDYcF95h7HoMTrC -->

### <a name="level-19-level-20"></a> Level 19 $\rightarrow$ Level 20

I used `./bandit20-do` to execute the binary referred to in the problem statement and found that it allows me to execute commands as `bandit20`. As such, to get the password for the next level I simply ran

```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

<!-- VxCazJaVykI6W36BkBU0mJTCM8rR95XT -->

### <a name="level-20-level-21"></a> Level 20 $\rightarrow$ Level 21

To be honest I had no idea how to solve this level and I had to consult some writeups online. I found that I had to basically:

1. Identify an unused port on localhost (this can be easily done by using `nmap`)
2. (a) Use `nc` with the `-l` flag to listen for incoming connections on the unused port on localhost and

   (b) Pipe `echo <level 20 password>` to the aforementioned `nc -l` command so the password is read when a connection is made by the port.

3. While the `nc` is running, run the `suconnect` binary to connect to the aforementioned unused port and read the password for level 19.

To accomplish 2 and 3 at the same time, with the help of an online tutorial I used `tmux` to start a new session with 2 terminals side by side.

![Double terminals using tmux](/staging/personal_blog/static/images/otw_bandit/bandit20.png)

After choosing a suitable port, on the first terminal I ran `echo <level 20 password> | nc -l localhost <port>`. While this was running, I switched to the second terminal and ran `./suconnect <port>`. This caused a connection to be made to `<port>` and the `<level 20 password>`, which is the output of the `echo` command, to be read by the `suconnect` binary. Since the password was right, the binary transmitted the password for the next level to the connected port on localhost, where it was printed in the console on the first terminal since `nc` was still listening on the port.

I also learnt that there is a way to accomplish this without using `tmux`, which is to run `nc` in the background by using the `&` option. This allows one to continue using the terminal as usual for running `suconnect` while having `nc` listening at the same time.

<!-- NvEJF7oVjkddltPSrdKEFOllh9V1IBcq -->

### <a name="level-21-level-22"></a>Level 21 $\rightarrow$ Level 22

I navigated to `/etc/cron.d` as directed and found a file called `cronjob_bandit22`, which referenced an executable called `cronjob_bandit22.sh` in `usr/bin`. I read the contents of the executable and found that the password to access `bandit22` was written to a specified file in the `/tmp` directory. I simply used `cat` to display the contents of that file and retrieved the password to access the next level.

<!-- WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff -->

### <a name="level-22-level-23"></a> Level 22 $\rightarrow$ Level 23

I looked at the directory as directed in the problem statement and noticed a file `cronjob_bandit23` which made references to `cronjob_bandit23.sh` in `/usr/bin`. Reading this shell script, I found that at the end a password is written to a specific file in the `/tmp` directory.

The name of the specific file the password will be stored in is determnined by the output of the command `echo I am user $myname | md5sum | cut -d ' ' -f 1` where `$myname` is the output of running the `whoami` command.

Since we are trying to get the password for `bandit23`, we need to discover the name of the file in the `/tmp` containing the password. I replaced `$myname` with `bandit23` and ran

```bash
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
```

which gave me a string which turned out to be the name of the file in the `/tmp` directory containing the password for `bandit23`.

<!-- QYw0Y2aiA672PsMmh9puTQuhoz8SyR2G -->

### <a name="level-23-level-24"></a> Level 23 $\rightarrow$ Level 24

By looking in `cron.d` as directed, I identified the relevant shell script. Its contents were:

```bash
#!/bin/bash

myname=$(whoami) # line 1

cd /var/spool/$myname/foo # line 2
echo "Executing and deleting all scripts in /var/spool/$myname/foo:" # line 3
for i in * .*; # line 4
do
    if [ "$i" != "." -a "$i" != ".." ]; # line 5
    then
        echo "Handling $i" # line 6
        owner="$(stat --format "%U" ./$i)" # line 7
        if [ "${owner}" = "bandit23" ]; then # line 8
            timeout -s 9 60 ./$i # line 9
        fi
        rm -f ./$i # line 10
    fi
done
```

Let's analyse this script line by line to see what it does and what we must do.

**Lines 1-2:** the `whoami` command is executed and stored in the variable `myname`. The working directory is then changed to the `foo` subfolder in the folder bearing the same name as the value of `myname` in `/var/spool`. My guess is that the expected output of `whoami` when this script is ran is `bandit24`, and I further verified this by navigating to the `/var/spool` folder and finding that `bandit24` is the only file with a 'bandit' name.

**Line 3:** a message is printed out to the console telling the user that all scripts in a particular folder, in this context `/var/spool/bandit24/foo` will be executed and deleted. The problem statement says that I will have to write a shell script which will be deleted once executed. This is probably where the script should be.

**Line 4:** this is initialising a for loop iterating through all the contents of the `/var/spool/bandit24/foo` folder, with the names of the files being stored in the variable `i`.

**Line 5:** indicates that during each iteration of the for loop there is an evaluation of whether `i` is _not_ the string representing the current directory (`.`) _and_ ([represented by `-a`](https://stackoverflow.com/questions/321348/bash-if-a-vs-e-option)) _not_ the string representing the parent directory (`..`). The execution of the rest of the code in the loop only continues if this evaluation returns `true`, and will continue with the next iteration of the for loop otherwise.

**Line 6:** a message is presented to the console indicating that the file `i` is being handled.

**Line 7:** the `stat --format "%U" ./$i` extracts the username of the owner of the file `i`. This username is then stored in the variable `owner`.

**Lines 8-9:** if the owner of the current file is `bandit23`, then line 9 is executed. Line 9 essentially tries executing the current file (the `./$i` at the end) and if the execution of the file takes more than 60 seconds a `SIGKILL` signal ('`-s 9`' from `man timeout` and `kill -l`) will be sent to kill the program.

**Line 10:** removes (deletes) the current file.

From analysing the script above, my idea was to write a script to be placed in `/var/spool/bandit24/foo` so that it is executed by `/usr/bin/cronjob_bandit24.sh`. The script will be something similar to `cronjob_bandit23.sh` and `cronjob_bandit22.sh` where the password for `bandit24` is written from `/etc/bandit_pass` to a file in `/tmp` for me to retrieve.

The script I wrote is:

```bash
#!/bin/bash
echo "Copying passwordfile /etc/bandit_pass/bandit24 to /tmp/bandit24_pass"
cat /etc/bandit_pass/bandit24 > /tmp/bandit24_pass
```

Initially I was encountering some problems with the password not being written to the target `bandit24_pass` file. Revisiting the `cronjob_bandit24` file in `cron.d` I found that the `cronjob_bandit24.sh` script will be ran either every minute or upon reboot. So I went back to the `foo` folder, created the script to retrieve the password, and waited for a minute. I then verified that the script I created disappeared as expected, but there was still no password file in `/tmp`.

After some digging online, I suspected that this might be due to a permissions issue, i.e. `bandit24` not having enough permissions to execute my password retrieval script. Sure enough, after creating the script in `foo` and running `ls -la` on it I found that there were no `x` (execute) permissions assigned to any users.

Therefore, after creating the script in `foo`, I quickly executed `chmod 777 <script name>` within a minute to change the permissions of the script. It was after this that the script ran as expected and I was able to retrieve the password for the next level.

<!-- VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar -->

### <a name="level-24-level-25"></a> Level 24 $\rightarrow$ Level 25

The only way to brute force through 10000 possibilities is to use a script. I decided to use a script to generate all 10000 possibilities then pipe the possibilities into a `nc` session as input.

My script `get_bandit25_pass.sh` is:

```bash
#!/usr/bin/env bash

password="<bandit24 password here>"

for ((i = 0 ; i < 10000 ; i++)); do
	printf "%s %04d\n" ${password} $i
done
```

and by executing `./get_bandit25_pass.sh | nc localhost 30002` I managed to retrieve the password for the next level.

<!-- p7TaowMYrmu23Ol8hiZh9UvD0O9hpx8d -->

### <a name="level-25-level-26"></a> Level 25 $\rightarrow$ Level 26

I found a sshkey for `bandit26` in the `bandit25` home directory. I copied the sshkey to a file on my local device, then tried logging in to the `bandit26` server using it, but was immediately logged out.

I tried to add bash commands at the end of the `ssh` command just like in level 18 in an attempt to carry out some discovery, but every command I tried seemed to cause the connection to hang, requiring me to have to manually terminate the connection attempt.

After some [research](https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/) I found that information about user accounts on the system such as home directory, user and group ID and more importantly, the shell. I found that the shell for `bandit26` was `/usr/bin/showtext`. Analysing the `showtext` file I found that it first sets the terminal emulator to linux, then executes `more` on a file called `text.txt` located in the home diretcory of `bandit26`, then closes the connection.

To be honest I was a little stuck and had to look at [a walkthrough](https://medium.com/@coturnix97/overthewires-bandit-25-26-shell-355d78fd2f4d) online for some clues. The first thing to note is that even though connection to `bandit26` automatically terminates, it terminates after printing some ASCII art for `bandit26` not present in previous bandit levels.

![ASCII art for bandit26 not present in other stages](/staging/personal_blog/static/images/otw_bandit/bandit25_1.png)

This corroborates the `showtext` script, and the `text.txt` which `more` is used display is probably the file which contains the `bandit26` ASCII art. Since the ssh connection is closed only after the `more` command terminates, to delay the automatic disconnection we can delay the `more` command from terminating.

Since the `more` command displays file contents one screenful at a time, we can delay the `more` command from terminating by resizing the screen to as small as possible before executing the `ssh` connection.

![Resized window preventing more command from terminating](/staging/personal_blog/static/images/otw_bandit/bandit25_2.png)

By reading the `man` page we can use `v` while `more` is executing to launch an editor for the `text.txt` file. While in the editor, we can use `:e /etc/bandit_pass/bandit26` to open the `bandit26` password file for editing, which gives us the password for `bandit26`.

<!-- c7GvcKlw9mC7aUQaPx7nwFstuAIBw1o1 -->

### <a name="level-26-level-27"></a> Level 26 $\rightarrow$ Level 27

Continuing on from the previous stage, to get the password for `bandit27` we need still need to obtain a shell so we can actually run some commands. It turns out that this can be done from within the `vim` editor launched previously by executing `:set shell=/bin/bash` while in the command mode of the editor and then using `:shell` to launch a bash shell.

Once we have a bash shell we can simply make use of the `bandit27-do` executable to retrieve the desired password from `/etc/bandit_pass/bandit27`.

<!-- YnQpBuifNMas1hcUFk70ZmqkhUU2EuaS -->

### <a name="level-27-level-28"></a>Level 27 $\rightarrow$ Level 28

First I change the working directory to `/tmp/bandit27` where `bandit27` has permissions to create files and folders. Then I executed `git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo` to clone `repo` to the current working directory. The password for the next level is quite straightforward to find once the cloning is successful.

<!-- AVanL161y9rsbcJIsFHuw35rjaOM19nR -->

### <a name="level-28-level-29"></a> Level 28 $\rightarrow$ Level 29

I cloned the repo as directed and analysed the `README.md` file. It displayed the credentials of `bandit29` with the password redacted. I executed `git log` to check the commit history, and found that there was a commit made with the comment "fix data leak", which came after one with "add missing data". My guess is that the editor accidentally commited the password for `bandit29` and then redacted it in the later commit to fix the data leak. So if I was able to revert the file back to the pre-redaction commit I should be able to retrieve the password.

Thus, I ran `git revert <commit ID of the fix info leak commit>` and I saw that the password for `bandit29` in `README.md` was no longer redacted.

<!-- tQKvmcwNYcFS6vmPHIUSI3ShmsrQZK8S -->

### <a name="level-29-level-30"></a> Level 29 $\rightarrow$ Level 30

After cloning, I started out by digging through the `.git` directory and the commit history, bur I didn't find anything helpful. However, since the password value in the `README.md` file says "no passwords in production!", I guessed that perhaps there are other pre-production branches which might be interesting to look at.

To find all the branches availabl, both local and remote, I executed `git branch -a`. I found that there were a few branches, one called `dev`. To switch to that branch, I executed `git checkout -b dev`. Reading `README.md` showed the password for `bandit30`.

<!-- xbhV3HpNGlTIdnjUrdAlPzc2L6y9EOnS -->

### <a name="level-30-level-31"></a> Level 30 $\rightarrow$ Level 31

I cloned the repository and did some digging but to no avail. It was only when I looked online at lists of commonly used `git` commands did I find a lead. Running `git tag` to show all the created tags shows that there is a tag called `secret` (which isn't applied to any commit). We can then use `git show secret` to reveal the annotation message associated with the tag, which is the password for the next level.

<!-- OoffzGDlzhAlerFJ2cAiz1D41JW1Mhmt -->

### <a name="level-31-level-32"></a>Level 31 $\rightarrow$ Level 32

This level requires us to push a file to the remote repository. Fortunately, I already had some experience doing this.

First, I used `vim` to create the text file specified in `README.md`. Then I tried adding the file to be tracked by git but found that the `.gitignore` file specified that `.txt` files were to be ignored. So I changed the `.gitignore` file and added `key.txt` to be tracked by git by running `git add key.txt`. Next, I commited my changes by running `git commit -m <commit message>`. Finally, I executed `git push origin master` to push the changes (the `key.txt` file) to the remote repository (`origin`) on the `master` branch. The password for the next level was then revealed in the status message of the push.

<!-- rmCBvG56y58BXzv98yZGdO7ATVL5dW8y -->

### <a name="level-32-level-33"></a> Level 32 $\rightarrow$ Level 33

To be honest I spent a good half an hour trying random stuff to try to understand how the uppercase shell was processing the input. I knew that I couldn't rely on the usual bash commands, so I was trying out bash variables like `$HOME` and `$PWD` but I didn't get very far.

Then I stumbled upon a [forum post](https://askubuntu.com/questions/590899/how-do-i-check-which-shell-i-am-using) with someone asking how to go about checking which shell they were using. The top answer was to use `echo $0`, but knowing that `echo` wouldn't work for me I just entered `$0`... and I magically obtained a shell!

![Escaping uppershell and obtaining a shell](/staging/personal_blog/static/images/otw_bandit/bandit32.png)

I then executed `/bin/bash` to switch to the familiar `bash` shell and now everything was 'back to normal'. I then tried to understand why entering `$0` worked. By looking at the `/etc/passwd` file I verified that `bandit32` starts up with `uppershell` as the default shell. From my research, `$0` is the current shell the user is in. So it turns out that when I was in uppershell I was actually in `sh`. I actually missed out a little detail which corroborates this: when in uppershell, the output of most executed commands begin with `sh : 1 : ...`, just like in `sh`. Therefore when I executed `$0` in uppershell what migh have happened is that `sh` resolved `$0` to 'current shell', i.e. `sh`, executed `sh` which gave me the shell.

It turns out that `uppershell` is executed as `bandit33` – this can be confirmed by running `whoami`. This means that retrieving the password is as simple as going to the `/etc/bandit_pass` folder and looking at the relevant file. This was a fun level.

(If you are stuck in uppershell, you can [terminate the `ssh` session](https://superuser.com/questions/467398/how-do-i-exit-an-ssh-connection) by hitting enter then `~.`)

<!-- odHo63fHiFqcWWJG9rLiLDtPm45KzUKy -->

## Conclusion

Connecting to `bandit33` gives the following message:

![The end!](/staging/personal_blog/static/images/otw_bandit/bandit33.png)

The end! This has been a long but extremely fun and fruitful journey. Some levels were pretty simple to me because I already had some experience with the necessary commands, and some levels forced mme to familiarise myself with new commands I've never used before. Some things I've learnt along the way include:

- using network utilities like `nc`, `nmap`, `openssl s_client`, and `telnet`
- analysing and writing bash scripts
- making `ssh` connection with private key
- understanding environment variables such as $0, $SHELL, $HOME etc.
- understanding cronjobs
- essentials like `grep`, `|`, `uniq`, `tr`, `file`, `find`, `diff`, `/dev/null`, `stdout`/`stderr` redirection, etc.

and many more...

The levels I found the most challenging were level 25 (the `more` level) and level 20 (make connection while listening on port), and the levels I enjoyed the most are level 13 (automatic `ssh` disconnect) and level 32 (uppershell).

This challenge took me around 2 weeks working on average 2h a day to complete (including writeup). I won't say that I'm an expert in any of the topics covered in this wargame, but I can say that it has helped me know what commands are out there and what their functions are. On to the next one!
