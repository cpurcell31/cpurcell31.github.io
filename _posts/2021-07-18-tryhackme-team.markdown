---
layout: post
title:  "Tryhackme: Team"
tags: THM
---

Machine Created By: dalemazza

Difficulty: Easy

Description: Beginner friendly boot2root machine

Tags: security, boot2root, Enumeration, Misconfiguration

## Enumeration

Let's start out by doing a port scan with nmap to see what's happening on this machine.

![Nmap Scan Results](/assets/THM-Team/nmap-THM-Team.png)

Okay, so we can see Port 21, 22, and 80 are open.
I did a quick check to see if ftp allowed anonymous login but to no avail.
Since Http is running on port 80, let's check out the website.

![Default Apache Page](/assets/THM-Team/apache-THM-Team.png)

Interesting, it's a default page but with a little hint for us to add team.thm to our /etc/hosts file
and the result is less default looking website! Let's run gobuster again and see what we can find

![Gobuster Scan 1](/assets/THM-Team/gobuster-THM-Team.png)

This time we have an images directory, an assets directory, a scripts directory, and a robots.txt file
I checked the robots.txt file first since those sometimes have something juicy in them and found a potential username

![Robots.txt](/assets/THM-Team/robots-THM-Team.png)

On top of that, we have a script.txt file that hints towards another script file with
a different extension that contains a username and password

![Gobuster Scan 2](/assets/THM-Team/gobuster2-THM-Team.png)

Using a lot of file extension testing and a bit of sudden realization the old script file was found

![Old Script](/assets/THM-Team/script-old-THM-Team.png)

## Gaining Initial Access

Hint: "As the 'dev' site is under contruction maybe it has some flaws? 'url?=' + 'This rooms picture'"

The file gives us a username and password for the ftp server. On the ftp server only one file is available and it gives another
hint. This time to add dev.team.thm to the /etc/hosts file and a small hint about where an id_rsa key could be found 

![Ftp File](/assets/THM-Team/newsite-THM-Team.png)

The new site is "under development" and contains a link to another page. The url for this second page caught my attention
immediately. Seeing /script.php?page= made me want to try a quick LFI to see if I could get lucky. Sure enough, inputting
/script.php?page=/etc/passwd gave an excellent response

![LFI #1](/assets/THM-Team/lfi1-THM-Team.png)

Going back to the hint about ssh config files, I did a quick check to confirm the default location for sshd_config, which,
turns out to be /etc/ssh/sshd_config. I then attempted another LFI and dumped the sshd_config file. It was a bit ugly
on the original output so I viewed the page source code to get a prettier version.

![LFI #2](/assets/THM-Team/lfi2-THM-Team.png)

We can clearly see that dale backed up his id_rsa key to the config file. A quick copy, plus removing all the #s, and 
not forgetting to add a blank new line at the end of the file and I had a serviceable key. I then ssh'd into the machine
as dale and found the first flag.

![SSH as Dale](/assets/THM-Team/user-THM-Team.png)

## Privilege Escalation

A good simple check to do when gaining access is seeing what sort of sudo permissions the user has with `sudo -l`.

![Sudo Privileges](/assets/THM-Team/sudopriv-THM-Team)

Here we see that dale has sudo permissions as gyles to execute `/home/gyles/admin_checks` which is a good first stop.
I checked to see what admin_checks did so I ran it with sudo as gyles.

![Admin Check 1](/assets/THM-Team/admin-check-THM-Team.png)

It seems to run the date command as part of its routine. I decided to check if it was running date without an exact path
by creating my own malicious date script and changing the PATH so it would pick it instead. However, this didn't give
the desired effect.

![Admin Check 2](/assets/THM-Team/admin-check-fail-THM-Team.png)

The next thing I tried was instead of typing "date" where the script requested it, I went for a different program "/bin/bash".

![Admin Check 3](/assets/THM-Team/admin-check-success-THM-Team.png)

    python3 -c "import pty; pty.spawn("/bin/bash")

admin_checks must have used to user supplied value to call whatever command directly, which, gives me access to gyles' account.
After I did a quick python shell upgrade and prepared for the next step.

## Gaining Root Privileges

Hint: "Is root running anything automated? ps I like PATH s"

The next step was to see what sort of freedom I had with gyles. "sudo -l" was a no-go since gyles has no sudo privileges.
I went ahead and setup a python simple http server on my kali box and downloaded linpeas onto the machine and ran it.

![Linpeas](/assets/THM-Team/linpeas-sh-THM-Team.png)

All of the super interesting results tagged by linpeas were relating to one thing: a writeable script
"/usr/local/bin/main_backup.sh". The script is fairly simple, but most importantly, I can write to it since gyles is
part of a the admin group. 

![Main Backup](/assets/THM-Team/main_backup-THM-Team.png)

The given hint for this step seems to ellude to a cronjob that root is running and more than likely it is related to this script.
So inserting a bash one liner into the script will hopefully give us root.

![Root](/assets/THM-Team/root-THM-Team.png)

Sure enough, we have root and the final flag.


## Lessons Learned

1. Web Directory and File Enumeration
2. Basic Local File Inclusion (LFI)
3. SSH Key Formatting
4. Simple Script Manipulation
5. Some Linux Enumeration






