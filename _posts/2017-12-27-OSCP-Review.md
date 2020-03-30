---
layout: single
title: "Offensive Security's PWK & OSCP Review"
header:
  overlay_image: oscp.png
---

On December 19, 2017 I received one of the most desired emails by aspiring Offensive Security enthusiasts and professionals...

> Dear Jack,
>
> We are happy to inform you that you have successfully completed the Penetration Testing with Kali Linux certification exam and have obtained your Offensive Security Certified Professional (OSCP) certification.

Man was I ecstatic! After a grueling 2 months of training in the OffSec Lab's and a long but successful 20 hours in the Exam, it all paid off at the end - I was finally an OSCP!

I could have only dreamed of this certificate, I never really expected it to become a reality so soon! All of that training, sleepless nights, and the enthusiasm to learn brought me here. So as I write this post, I want to share my thoughts, experiences, and some tips for those who are aiming to achieve the OSCP!

## Background & Experience

Before I delve into the PWK Course and the OSCP I want to provide you with some information on my background and experience. At time of writing this post I have been in the InfoSec Industry for ~3 years now. A lot of my experience came from self-education, spending countless hours at home and in front of my books learning new tools and techniques. Much of what I learned was put to the test at work where I carried out internal pen tests, security assessments, reverse engineering of malware (more like debugging), and such of that matter. At the same time, I supplicated my studies with practice - such as competing in CTF's, practicing on VulnHub VM's, and in the HackTheBox Labs. For those curious on the specifics of my studies, keep reading as I will delve more into this in the tips section. But for now, let's get into the real meat of things!

## The PWK Course

The overall OSCP experience can be seen as 3 part process. The PWK Course, PWK Lab, and the OSCP Exam. You have an option to register for 30, 60, or 90 days of lab time. Once you register, you select the week you want to start your studies - specifically a Saturday/Sunday is when a new course beings. It is encouraged to register 10-30 days before your expected start week, since time slots fill up really fast! On your assigned course start date, you’ll be provided access to download all your course materials, including the 8-hour Offensive Security PWK course videos, the 375-page PWK PDF course, and your VPN lab access. Once your lab time starts - it will be a continuous block, meaning that you can't stop/start it at any time after the start date.

When starting my OSCP journey I opted for about 60 Days in the labs (2 Months). I thought that this would be plenty of time for me to go through the PDF, Videos, and Lab, and that it would provide me with enough room if some days/weeks would be too hectic for me to study.

It was around 7PM on October 14th when I received my PWK VPN, and Course Material. I instantly got to work going through the PDF and supplicating each chapter with its respective video. It's recommended that you go through both the PDF and Videos as the videos sometimes have more details then the pdf - which should help shed some light on a few things. The PDF/Videos cover a lot of sections including Linux Basics, Essential Tools, Enumeration, Information Gathering, Buffer Overflows, Privilege Escalation, Client Side Attacks, Web Application Attacks, Pivoting, and Metasploit.

I spent about a week going through the whole PWK Course and a few of the Exercises, and spent a lot of time on the Buffer Overflow section, as that was one of the topics I knew I wanted to ace! Overall, for me, the PWK Course was honestly a refresher - the only thing that was beneficial for me was the Buffer Overflow and Pivoting sections of the course. I only completed about half of the exercises before I decided to jump into the PWK Labs.

Now do note, that the PWK Course doesn't provide you with everything you need to know! The Course is there to help build the foundation and teach you the initial basics you need to succeed. There will be countless things that you will still need to learn/research yourself during your time in the labs - so I suggest you brush up on your Google Fu!

## The PWK Lab

The PWK Lab is the meat of the PWK Course. This is where most of your learning takes place. The lab has about 50 Machines total of varying OS's, vulnerabilities, and misconfigurations separated in 4 different network sections - Public, IT, Dev, and Admin. Your goal is to get access to the Admin network, but for some, the goal might be different - so don't let it get to you if you can't get into the Admin network!

All the machines in the lab vary in difficulty - some are easy, while some are "bang your head on the table for hours on end" hard. There might be a time in the labs where you think a machine is invulnerable... and you might be right, but that's not how the course was set up. The PWK Lab was configured to simulate a real live network environment, which means that some machines interact with one another and could be compromised by Client Side attacks. Other machines on the other hand might have information on them that can lead to the compromise of another machine in the lab. In general, you should never leave any stone unturned and properly enumerate. If you find yourself stuck, you can always access the OSCP Forum and IRC to ask for help or to browse for hints. Don't worry if you need to do so - its part of the learning process! Just don't get aggravated if most of the answers you get are "__Try Harder__" or "__Enumerate!__", because chances are, you didn't enumerate properly and missed a critical piece of information.

At first when I got into the Labs I was overwhelmed, I didn't know where to start! Thankfully, the PWK Course goes over some simple enumeration scans, which can aid you in starting your attack. During the whole time I used OneNote to keep track of all my notes, scans, commands, and screenshots.

Upon jumping into the lab, I ran a small set of scans with Nmap and came to notice a specific service running on one of the machines, one that I previously saw when doing a machine in HackTheBox! I got so excited that I attacked the machine right away - within an hour, I had root access and managed to learn a few new things! It was honestly a great start. Within 30 days, I managed to root 38 of the devices - including Pain, Sufferance, Ghost, and Bethany - and had access to the Dev and IT network. At that point, I opted in for the OSCP exam and locked in the time for December 16th at 9AM.

At first, I went through the Lab using Metasploit and some manual exploitation. For the last 30 days, I went back through all the machines I exploited via Metasploit and managed to do them all manually - either by porting over the Metasploit Exploits via Python, or using third party scripts and tools to connect to services such as MSSQL, etc. In all honesty, this was a great idea as it helped me better understand exploit writing, and it aided me during my OSCP Exam.

## The OSCP Exam

This arduous 24-hour exam in all honesty is brutal, and it has every right to be! Its initial goal is to prove that you have a good foundation of the penetration testing cycle, and to prove that you actually learned and retained your training. For the exam you will be allocated 6 machines, 5 Exam Machines and 1 Windows Test VM just like in the Labs - this VM will be your debugger for exploit writing. Each machine has certain objectives that you need complete in order for your points to count. Along with that, Metasploit is restricted to only one machine, but I suggest that you don't use Metasploit, and save it as a last resort. In order to pass you need to score 70/100 points, each machine having a different amount of points depending on the objectives. I highly suggest you read the [OSCP Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md) for more details on what is and isn't allowed during the exam.

Finally - December 16th came around. I woke up around 7:30AM - ate some breakfast, drank some tea, and went for a walk to relax and catch my thoughts. By 8:30 I was sitting at my desk, all my workspaces in Kali were configured the way I liked, OneNote was set up for the exam, and I queued up a few hours of Deadmau5 and some Drum and Bass to play in my headphones as I worked. Sure enough, at 9AM I got the email from OffSec with my Exam VPN and instructions. I took 15 minutes to read everything and make a mental note on what I needed to do. By 9:30 I was off and taking on the first machine.

2 hours after my initial start time, I finished my Buffer Overflow machine - but not without any issues. I actually had to reach out to OffSec to reset the machine as the service wasn't properly working. Once reset, I was able to exploit the machine and attained a root shell! I was a nervous wreck, and the butterflies in my stomach were acting up, but by 12PM I had two machines rooted with 35 points under my belt! At this point I decided to step away for an hour and take a small break.

After a relaxing break, and some food in me, an hour later I was able to attain a limited shell on another device using an actually pretty complex and interesting method. Shortly after, I was able to attain a high privilege shell, brining me to 55 points! In all honesty I overcomplicated the process and missed a critical piece of information - I only found it when I went back and enumerated again!

At around 6PM I hit a road block, with two machines left I couldn't for the life of me find an entry point. I enumerated all I could but kept coming up with blanks or kept going down rabbit holes. After about an hour of hitting dead ends I opted to take a small 1 hour break to eat and watch some TV. Once my break was over, I got back and started enumerating again, and quickly spotted something while using Burp. After a few hours of trial and error, by 11PM I was able to get a limited shell, brining me up to 67.5 points!

Oh man, was I ecstatic - I did a victory lap around the house and played the [Try Harder](https://www.offensive-security.com/offsec/say-try-harder/) song to celebrate! All I needed was a root shell and I pass, easy! Right...? Wrong!

For the next 4 hours I was at another roadblock. I couldn't find a way to escalate privileges - even though I went through the process twice. Nothing seemed to work. I found myself bouncing back between the privilege escalation and the other machine, hoping to find a way to get the final limited shell, or to attain root. By 2AM I gave up trying to get root and made up my mind that I need the other limited shell to pass.

At this point I was exhausted, 18 hours into the exam and I was so close! I told myself that I will not fail, that I will "__Try Harder__"... and then it hit me. The second I came to realize that I was trying "too hard" was like someone taking a bat to the back of my head... I was following a dead end for the last few hours! The vulnerability that I was trying to exploit was never taught in the OSCP, it was never found in the labs - I only knew of it because of my studies! I took a step back, and took a few minutes to breathe and make some tea. 

I came back to the machine with a fresh mind and the mindset of "think simple". And it worked! I ran another Nikto scan on a directory and it bestowed me with a simple vulnerability. But even at this point I wasn't able to exploit it... till I saw something interesting. A quick Google search led me to a few thing and after some trial and error, by 3AM I had another limited shell, brining me up to 77.5 points - enough to pass!

## Wrapping it Up

At this point I called it quits, I went back to gather all the screenshots and to make sure that I had all the requirements. By 4AM I was happily asleep - knowing that I passed! I woke up around 1PM the next day and began working on my report which was about 89 pages long and pretty detailed. I submitted my report at around 4AM Monday morning - I went to a concert with my brother that evening haha - and by Tuesday morning I got my response that I passed!

All I can say is - wow! I have the upmost respect for anyone that takes the OSCP Challenge and passes it. This is by far one of the hardest challenge that I have done to date and it has taught me a plethora of new things that I can utilize in my day to day work activities. I sincerely want to thank OffSec for this amazing experience and opportunity, maybe I'll do the OSCE next!

## Tips & Recommendations

I know that many of you who will be reading this post will ask for tips/recommendations on either preparing to take the OSCP or on how/what to do during the exam. Well not to worry - in this section I will break down and include a lot of the materials I used to prepare for the OSCP as well as some tips/tricks to use for the exam.

### Prerequsites:

In the PWK Course, OffSec states that you need to understand the following fundamentals to take the course...

> Penetration Testing with Kali Linux is a foundational security course, but still requires students to have certain knowledge prior to attending the online training class. A solid understanding of TCP/IP, networking, and reasonable Linux skills are required. Familiarity with Bash scripting along with basic Perl or Python is considered a plus. This advanced penetration testing course is not for the faint of heart; it requires practice, testing, and the ability to want to learn in a manner that will grow your career in the information security field and overcome any learning plateau.

If you are somewhat unfamiliar with these basics, here are some links to help you learn the required materials:
* TCP/IP & Networking
  - [Networking Basics: TCP, UDP, TCP/IP and OSI Model](https://www.pluralsight.com/blog/it-ops/networking-basics-tcp-udp-tcpip-osi-models)
  - [Common Ports & Protocols](https://pbs.twimg.com/media/DP7axHKUEAALlJB.jpg:large)
  - [Security+ Section 1: Network Security](https://www.professormesser.com/security-plus/sy0-401/sy0-401-course-index/)
  - [Nmap Basics](https://nmap.org/bennieston-tutorial/)
* Linux & Bash Scripting
  - [OverTheWire - Bandit](http://overthewire.org/wargames/bandit/)
  - [Bash Scritping Tutorial](https://linuxconfig.org/bash-scripting-tutorial)
  - [Null Byte - Linux Basics](https://null-byte.wonderhowto.com/how-to/linux-basics/)
* Python
  - [Codecademy - Python](https://www.codecademy.com/learn/learn-python)
  - [Python 2.7.14 Documentation](https://docs.python.org/2/index.html)

### Practice:

Now that you have a fundamental understanding of the basics, you need to practice... a lot! If are pretty new to Penetration Testing and think that taking the OSCP will teach you - then you are dead wrong! You need a lot of previous training and experience to even attempt something like the OSCP.

The following materials below will help you take the first steps into Penetration Testing, and for those who are already experienced, it will help you practice and expand your skills.

* Videos
  - [Cybrary - Penetration Testing and Ethical Hacking](https://www.cybrary.it/course/ethical-hacking/)
  - [Cybrary - Advanced Penetration Testing](https://www.cybrary.it/course/advanced-penetration-testing/)
  - [Cybrary - Web Application Penetration Testing](https://www.cybrary.it/course/web-application-pen-testing/)
  - [HackTheBox Walkthroughs by IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA/videos)
  - [PwnFunction Videos](https://www.youtube.com/channel/UCW6MNdOsqv2E9AjQkv9we7A)
  - [LiveOverflow: The Secret step-by-step Guide to learn Hacking](https://www.youtube.com/watch?v=2TofunAI6fU)
* Books
  - [Penetration Testing: A Hands-On Introduction to Hacking](https://www.amazon.com/Penetration-Testing-Hands-Introduction-Hacking-ebook/dp/B00KME7GN8/ref=sr_1_fkmr0_1?s=digital-text&ie=UTF8&qid=1514402732&sr=1-1-fkmr0&keywords=hiking+georgia+weidman)
  - [The Hacker Playbook 3: Practical Guide To Penetration Testing](https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing-ebook/dp/B07CSPFYZ2)
  - [The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470)
  - [Black Hat Python: Python Programming for Hackers and Pentesters](https://www.amazon.com/Black-Hat-Python-Programming-Pentesters/dp/1593275900/ref=sr_1_1?ie=UTF8&qid=1514402830&sr=8-1&keywords=Black+Hat+Python%3A+Python+Programming+for+Hackers+and+Pentesters)
  - [Hacking: The Art of Exploitation, 2nd Edition](https://www.amazon.com/Hacking-Art-Exploitation-Jon-Erickson/dp/1593271441/ref=sr_1_fkmr0_1?ie=UTF8&qid=1514402853&sr=8-1-fkmr0&keywords=Hacking%3A+The+Art+of+Exploitation+Paperback+%E2%80%93+7+Feb+2008)
* Practice Labs
  - [VulnHub](https://www.vulnhub.com/)
    - OSCP like VMs:
      - [Kioptrix 1-5](https://www.vulnhub.com/?q=Kioptrix&sort=date-des&type=vm)
      - [FristiLeaks: 1.3](https://www.vulnhub.com/entry/fristileaks-13,133/)
      - [Stapler: 1](https://www.vulnhub.com/entry/stapler-1,150/)
      - [PwnLab: init](https://www.vulnhub.com/entry/pwnlab-init,158/)
      - [Brainpan: 1](https://www.vulnhub.com/entry/brainpan-1,51/)
      - [Mr-Robot: 1](https://www.vulnhub.com/entry/mr-robot-1,151/)
      - [HackLab: Vulnix](https://www.vulnhub.com/entry/hacklab-vulnix,48/)
      - [VulnOS: 2](https://www.vulnhub.com/entry/vulnos-2,147/)
      - [SickOS: 1.2](https://www.vulnhub.com/entry/sickos-12,144/)
      - [SkyTower: 1](https://www.vulnhub.com/entry/skytower-1,96/)
  - [HackTheBox](https://www.hackthebox.eu/)
    - Practice on the Retired Machines too... trust me!
  - [Pentestit Labs](https://lab.pentestit.ru/) (Advanced Only!)
  - [CTF365](https://ctf365.com/)
  - [PentesetLab - Bootcamp](https://pentesterlab.com/bootcamp)
  - [Exploit Exercises - Mainsequence](https://exploit-exercises.com/mainsequence/)
  - [OverTheWire - Natas](http://overthewire.org/wargames/natas/)
* Study Materials & Guides
  - [Awesome Pentest](https://github.com/enaqx/awesome-pentest)
  - [Security Notebook](https://xapax.gitbooks.io/security/content/)
  - [Spawning a TTY (Interactive) Shell](https://netsec.ws/?p=337)
  - [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
  - [Metasploit Fundamentals](https://www.offensive-security.com/metasploit-unleashed/metasploit-fundamentals/)
  - [Creating Metasploit Payloads](https://netsec.ws/?p=331)
  - Windows Privilege Escalation
    - [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
    - [Windows Privilege Escalation - Checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
    - [Quick Notes](https://github.com/codingo/The-Security-Handbook#windows-privilege-escalation)
  - Linux Privilige Escalation
    - [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
    - [Linux Privilege Escalation Scripts](https://netsec.ws/?p=309)
    - [Exploit Exercises - Nebula](https://exploit-exercises.com/nebula/)
  - Buffer Overflows
    - [Exploit Writing Tutorial Part 1 : Stack Based Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
    - [Exploit Writing Tutorial Part 2 : Stack Based Overflows – Jumping to Shellcode](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/)
    - [Intro to x86 Assembly](http://www.opensecuritytraining.info/IntroX86.html)
    - [Exploit Exercises - Protostar](https://exploit-exercises.com/protostar/)

I know that there is a ton of material here, and it might seem overwhelming at first - but do know that much of these topics overlap each other once you begin studying offensive security. Remember, it takes time to learn - you need to enjoy the process of learning, or you will never get to your end goal! Take it slow, start with the basics, and work your way up.

### Exam Tips:

As with everything, there are always certain things that you should know and be doing during the PWK Lab and OSCP Exam, these following tips should help you stay on focus and to stray away from rabbit holes.

1. Enumerate, Enumerate, Enumerate!
2. Simple Nmap Scans w/ Script Scanning are your friends!
    - TCP: `nmap -sS -sV -sC -n [IP]`
    - UDP: `nmap -sU -sV -n --top-ports 200 [IP]`
3. Enumerate SNMP (UDP 161) if it's open!
    - `snmp-check -t [IP] -c public`
    - This will show other open ports/running services and applications!
4. Enumerate SMB (TCP 139/TCP 445) if it's open!
    - `enum4linux [IP]`
    - This will show open shares, anonymous logins, etc.
5. Run nikto on interesting directories!
    - `nikto -h http(s)://[IP]:[PORT]/[DIRECTORY]`
6. DirBuster over dirb. Opt for using the medium wordlist for better results!
    - `/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt`
7. Check for anonymous logins for FTP/SMB!
    - `ftp [IP]` 
      - Username: `anonymous` Password: `anonymous`
    - `smbclient -L \\[IP]`
      - Username: `root` Password: None
8. Check for WebDav! Nmap script scan should pick it up! If not...
    - `davtest -url http(s)://[IP]`
9. Don't overthink it! Try low hanging fruit first!
    - Password the same as Username?
    - Username/Password combo of `admin:admin`?
    - Google the Documentation. Default Credentials/Login?
10. Rotate machines every 3-4 hours. Don't tire yourself out!
11. Have an idea? But it seem impossible? Try it... you never know! =)
12. Take frequent breaks. Opt for 10 minute break every 2 hours.
13. Eat and drink! Make time for Lunch, and Dinner. Your brain needs food to function.
14. Limit caffeine intake, 1-2 cups of coffee is okay! But, drink Tea and Water.
15. Don't have any snacks next to you. If you're hungry, walk to the kitchen for a snack, this will make you walk away from your PC and will help clear your mind.
16. Breath... relax... you got 24 hours!
17. Organize your notes, take screenshots, and document everything!
18. A few days before the exam create and edit your report outline.
19. In the PWK Lab, practice the Buffer Overflows till you can do them by heart and without notes.
20. Don't give up to easily, and most importantly... "__Try Harder!__".
