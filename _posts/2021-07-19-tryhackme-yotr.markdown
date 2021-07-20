---
layout: post
title:  "Tryhackme Room: Year of the Rabbit"
categories: THM
---

Machine Created By: Muirlandoracle

Difficulty: Easy

Description: Time to enter the warren...

Tags: puzzle, challenge, boot-to-root, web

## Enumeration

First off, ensuring my volume is turned up as intended by the creator I began with a quick nmap port scan

![Nmap Scan](/assets/THM-YotR/nmap-THM-YotR.png)

We can see that ftp, ssh, and http are running on the machine. Since ftp is running its worth giving a quick
check to see if anonymous login is allowed.

![ftp anonymous login](/assets/THM-YotR/ftp-anon-THM-YotR.png)

No success there so let's turn our attention to http. The index page is the default apache page so let's see if 
we can enumerate anything open in the background.

![Gobuster Enumeration](/assets/THM-YotR/gobuster-THM-YotR.png)

The only result is an assets directory which contains two files: `RickRolled.mp4` and `style.css`. RickRolled is exactly
what you would expect but the style sheet has a little hint inside.

![style.css](/assets/THM-YotR/style-css-THM-YotR.png)

Upon visiting the sup3r s3cr3t php file we are greeted by an alert telling us to disable javascript.

![Advice](/assets/THM-YotR/js-THM-YotR.png)

After disabling javascript we are greeted by none other than Rick Astley who apparently has a hint for us.

![Rick Roll 2](/assets/THM-YotR/rick-again-THM-YotR.png)

The audio hint is a loud burping sound plus a text-to-speech naration telling us we are looking in the wrong place.
Now this could either mean we fell down the rabbit hole or a hint to tell us to use burpsuite.

![Burp](/assets/THM-YotR/burp-THM-YotR.png)

Turns out burp was the way to go. We are given the name of a hidden directory. Which contains a file titled HotBabe.png

![Hidden Directory](/assets/THM-YotR/hidden-THM-YotR.png)

Time to see if there is anything hidden in this picture. First I ran it through binwalk, the result was nothing out
of the ordinary. Then I ran strings to get the following output:

![Strings output](/assets/THM-YotR/strings-THM-YotR.png)

## Gaining Initial Access

As we can see we are given an ftp username and a list of possible passwords. Running them through hydra should get a hit.

![Hydra](/assets/THM-YotR/hydra-THM-YotR.png)

Using those login credentials for ftp lets us access a single file called `Eli's Creds.txt`. However, the file looks
like a bunch of nonsense. But, luckily I recognized this nonsense from another puzzle I have done.

![Eli's Creds](/assets/THM-YotR/brainf-THM-YotR.png)

Ladies and gentlemen, this is brainfuck, a famously weird programming language. Running this through a brainfuck decoder
gave a nice result.

![Decoded](/assets/THM-YotR/decode-THM-YotR.png)

Now we can ssh into the machine as Eli.

![SSH](/assets/THM-YotR/eli-THM-YotR.png)

## Privilege Escalation

Starting off, we are greeted by a message to Gwendoline from Root. The message hints towards a secret message hidden in
a secret spot on the machine.

A lot of enumeration later and I found a "s3cr3t" directory in /usr/games that contained a single file. A file with 
a potential password for gwendoline.

![Gwen Password](/assets/THM-YotR/gwen-pass-THM-YotR.png)

Sure enough a quick su to gwendoline proved it was their password and we have our first flag.

![Su Gwen](/assets/THM-YotR/gwen-su-THM-YotR.png)

## Gaining Root Privileges

Since we have the password for gwendoline, there is no harm in doing a quick `sudo -l` to see what they can do.

![sudo -l](/assets/THM-YotR/user-THM-YotR.png)

It looks like gwen has permissions to use vi on her file user.txt as anyone but root. Or so it seems.
Luckily there is a vulnerability with this exact kind of sudo permissions on this version of sudo. 

    sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt

From what I've read about this, when supplied a user id of -1 (or 4294967295) sudo fails to parse the value and defaults
to 0, the id of root. This bypasses the restriction on sudo as root. Therefore, we can run vim as root and subsequently
become root by inputting this command into vim.

    :!/bin/bash

![Vim as root](/assets/THM-YotR/root-THM-YotR.png)


## Lessons Learned

1. Try the Obvious - During this challenge, I missed a couple of easy things initially by dismissing something
"too obvious". Most notably, I lost a good chunk of time on the rick-roll hint by not trying burpsuite right away.

