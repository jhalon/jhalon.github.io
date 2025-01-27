---
layout: single
title: "So You Want To Work in Cyber Security?"
header:
  overlay_image: cybersecurity-bg.jpg
---

It goes without saying that being a Professional Penetration Tester is *considered* to be one of the "cooler" jobs in InfoSec. I mean, let's be honest here - who wouldn't want to break into buildings, and hack companies like Elliot from [Mr. Robot](https://en.wikipedia.org/wiki/Mr._Robot), or carry out crazy hacks against banks and casinos like in the [Oceans Series](https://en.wikipedia.org/wiki/Ocean%27s_(film_series)), all while doing it legally?

While it might seem that being a hacker for hire is all fun and games after watching a ton of episodes of Mr. Robot - which it is - it also has its downsides like every other job.

Working as a security consultant, I get asked a lot of questions on how to break into security or penetration testing, and what skills one must need to achieve such a job. Unfortunately, a lot of those asking me these questions are hoping for a "__one shot solution__" such as _"If you learn <u>this</u> and <u>this</u> you'll be golden!"_ Unfortunately, and I hate to break it to you, it really isn't that easy....

- First of all, to work in Security you need to be willing to continuously learn new things on the fly and or quickly at home.
- Secondly, you need to have a strong foundational understanding of network and web security, as well as an understanding of at least one coding and scripting language. 
- Third of all, you need to have decent soft skills - ones that will allow you to communicate with your team and clients, and ones that will allow you to write professional reports. 
- Fourth of all, you need to be willing to accept the fact that sometimes the work or projects you'll be doing will be boring or repetitive. 

> __NOTE__: Before you continue reading, take note of this. The previous iteration of this blog post has been active since 2018 and has been widely shared in the security community to many beginners. A lot has changed in security since then, including my knowledge. As such, I have opted to re-write a good chunk of the blog post in order to ensure that it's up to date with today's standards, and that it answers many questions that beginners have. This post is specifically focused around becoming a pentester, but whether you're going into defense or offense, the advice given here applies to everyone.
> 
> Additionally, do note that a lot of the advice I am giving you is based off of my own experiences, so always take this information with a grain of salt.
> 
> One thing I want to highlight prior to this post is... don't be discouraged when you don't get a security position fresh out of college or when transitioning from another field. This field has advanced so far and so fast that you seriously need to have a solid understanding of fundamentals and core technical concepts to stand a chance. 
> 
> I've said this before and I will say it again - **SECURITY IS NOT AN ENTRY LEVEL FIELD**! You can call me a gatekeeper, or whatever, but I'm just being realistic. It will take a lot of time and dedication to break into security if you have little to no experience, but I do hope this blog will help point you in the right direction and help you achieve your goals.

With that being said, let's get into the nitty gritty details of breaking into security!

## Understanding The Fundamentals

Before we dive into the technical skills required to be a successful pentester or even have a successful security career, it's crucial to first cover the most important aspect of security: **the fundamentals**. 

No matter how sophisticated the tools and techniques at your disposal may be, without a solid understanding of the fundamentals of computers and security, you won't be able to effectively analyze, attack or even defend systems. The fundamentals form the foundation upon which all technical knowledge is built. Mastering these principles ensures that you can approach each task you do with a clear understanding of why certain actions are necessary and how they impact the security landscape as a whole. Essentially, if you deeply understand a specific technology and how it works, it's so much easier to attack and defend that technology than if you scraped the surface by learning the most common misconfigurations and exploits.

Let's first start by covering the essential skills that you need to understand. These fundamental skills will serve as the foundation for a successful career in security.

So what are these "core fundamentals" that everyone in security should know? 

- **Networking**
	- **IP Addresses**: Understand both IPv4 and IPv6 and how they are used.
	- **Ports**: Understand common ports and the services they correspond to (HTTP/HTTPS, SSH, etc.).
	- **CIDR Notation**: Understand how to define and calculate network ranges using CIDR.
	- **TCP/IP Stack**: Understand the layers in the TCP/IP model as well as how and what type of data flows through each layer.
	- **Subnetting**: Understand how to divide networks into smaller subnets and calculate network masks.
	- **DNS**: Understand how the Domain Name System works by knowing how domain names are resolved into IP addresses and vice versa.
	- **Routing, Switching, and Firewalls**: Understand how routers and switches work to direct network traffic and how firewalls (and VLANS) are used to isolate traffic.
- **Encryption and Cryptography**:
	- **Basic Cryptography**: Understand the difference between symmetric vs. asymmetric encryption, know what hashing is, and what Diffie-Hellman is.
	- **SSL/TLS**: Understand how SSL/TLS work and how they are used to encrypt network traffic.
	- **Common Algorithms**: Become familiar with common encryption algorithms like AES, RC4, RSA, and hashing algorithms such as SHA1, and MD5.
- **Operating System Knowledge**:
	- **Windows Internals**: Understand the basics like file systems, user accounts, the registry, event logs, kernel, userland, and basics around process and memory management.
	- **Linux Internals**: Become familiar with the file system structure, user permissions, processes, and simple things like daemons.
	- **Command Line Proficiency**: Become familiar with system commands and learn how to use the Windows Command Prompt and Linux Bash Terminal.
- **Web Applications:
	- **Basics**: Understand HTTP/HTTPS, request-response cycles, REST APIs, and common web architectures.
	- **Session Management**: Understand how sessions are managed, including cookies, tokens, and secure session handling.
	- **Backend Basics**: Understand a common web application stack, and how data is handled on the backend of the application via technologies like SQL.
- **Active Directory**:
	- **Directory Structure**: Understand the organizational structure of Active Directory (AD), such as domains, forests, and organizational units (OUs).
	- **User and Group Management**: Understand how users accounts and groups are managed, and understand the basic permissions within AD.
	- **Authentication Protocols**: Become familiar with and understand how NTLM and Kerberos works, and how they are used to authenticate users.
- **Basic Malware and Threats**:
	- **Malware Types**: Understand the different types of malware such as viruses, worms, ransomware, rootkits, and how they can infect systems.
	- **Threat Vectors**: Understand the different threat vectors and attack types such as phishing, social engineering, impersonation, etc.
- **Common Attacks and Vulnerabilities**:
	- **Web Vulnerabilities**: Become familiar with the OWASP Top 10, and common attacks like Cross Site Scripting (XSS), SQL Injection, Cross Site Request Forgery, Denial of Service, etc.
	- **Operating System Attacks & Vulns**: Understand basic system exploits and attacks such as Buffer Overflows, Memory Injection, Race Conditions, Privilege Escalation, etc.

Now, I know a lot of beginners right now who are reading this are either **a)** panicking, **b)** overwhelmed, or **c)** no longer reading this and have returned to playing videos games - c'est la vie. For those who are still sticking around, let me start by saying... "I know it's a lot! I've been there before. Relax."

Rome wasn't built in a day, and neither will your security career. Remember when I said "Security Isn't an Entry Level Field"? Well a good chunk of people will want to see me burn for saying something like that, call me a gatekeeper and some bad words, but this just proves my point. There is a lot of prerequisite foundational knowledge that one must have to work in security, something a 6 month degree program, and unfortunately, even a college education might not teach (more on this later).

But that doesn't mean you can't break into security, so don't let anything discourage you! If you are a beginner or wanting to transition from a different field entirely then it will just take some time and dedication on your part to learn all of this. Remember, this isn't a race. Your goal shouldn’t be to absorb everything as quickly as possible. Instead, focus on learning things slowly and properly. That will pay off way more in the long run than rushing through topics without fully understanding them.

I'm not saying you need to be proficient in **ALL** of the fundamentals before you go out and apply for an entry level job, but you have to at least understand a good chunk of this and be able to recite this at an interview. 

These foundational skills are going to be the main driving point in helping you learn and most importantly **understand** the more in-depth technical skills that are discussed in the next section. Because at the end of the day, if you don't actually understand how something works, how do you expect to effectively attack or defend it, or even perform your job properly? Without a solid understanding of the fundamentals and core technical concepts, it’s nearly impossible to tackle more complex security problems or make informed decisions in real-world situations.

So, with that aside. Where can you learn all of this? Well thankfully in today's day and age (2025) unlike 2008-2012 when I first started out, there are a lot of free resources on the internet that can help teach you not only the security basics, but computer basics as well.

For starters I recommend you look at, and even take the following courses:

- [CS50: Introduction to Computer Science](https://pll.harvard.edu/course/cs50-introduction-computer-science)
- [CS50: Introduction to Cybersecurity](https://pll.harvard.edu/course/cs50s-introduction-cybersecurity)
- [Professor Messer’s CompTIA 220-1102 A+ Training Course](https://www.professormesser.com/free-a-plus-training/220-1102/220-1102-video/220-1102-training-course/)
- [Professor Messer’s CompTIA N10-009 Network+ Training Course](https://www.professormesser.com/network-plus/n10-009/n10-009-video/n10-009-training-course/)
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [TryHackMe: Pre Security & Cyber Security 101](https://tryhackme.com/r/hacktivities?tab=roadmap)

Now you don't have to take all of these and in the specified order, these are just suggestions. But if you are stuck and don't know where to being, then I recommend following the decision flow tree below to decide where you should start.

<p align="center"><a href="/images/cert-flow-chart.png"><img src="/images/cert-flow-chart.png"></a></p>

One thing I want to iterate here is don't worry about taking the certification exams just yet, we will cover certifications later in the blog post! For now, just focus on learning, retaining, and understanding the concepts presented in the courses.

Additionally, the CS50 courses are also great, but these are college courses, so some previous knowledge and experience in IT is assumed. If you finished Security+ or are just looking for additional supplemental education to learn coding and more security techniques, then I highly recommend you take those courses! 

> "_But Jack! There's X and Y courses that people can take! It only costs...._"
> 
> Okay, let me stop you right there! My aim here is to provide people with mostly **FREE** resources and resources that I have personally vetted. If you have suggestions, let me know so I can vet them and add them!
> 
> But there are a lot of paid courses taught by people who should never be teaching in the first place, let alone be considered an "expert". This kind of practice negatively impacts beginners who don't know any better and can easily be misled. As a result, they don't learn much, it sets them back and wastes their time and money. We will discuss this further in the "Education" portion of this blog.

Now that you have a solid foundation and understanding, let's move onto the technical skills! 
## The Technical Skills:

Ah yes, the technical skills, the lifeblood of a security professional. While it’s true that many professionals in the security field may focus on a specific niche or specialty - like Network Pentesting or Web Application Security - but if you work as a security consultant then it's possible you'll be required to work across multiple domains and won’t always have the luxury of focusing on just one area. 

I personally believe that you actually need to have a breadth of knowledge in multiple technical fields to succeed and even excel as a pentester. But through my experience two __<u>very</u>__ important technical skills are needed for day to day projects.

So, what two skills are important? Well, they are Web Security and Network Security.

"_Why these two?_" You may ask.... Well, web applications have become a central part of nearly every business, and with their prevalence comes a greater attack surface - making Web Security a top priority. On the other hand, Network Security is just as critical, as networks are the backbone of all communication and organizations, meaning that securing them is foundational. It's essentially a catch all skill for any offensive or defensive security folks, because it's crucial to understand if you want to attack or defend an entire infrastructure of an organization.

Regardless, if you want to focus on a different specialty like Reverse Engineering or Hardware Hacking rather than Web Apps and Network Pentesting, then by all means, focus on that and learn as much as you can. However, you should still learn both of these disciplines to become a more "well versed" professional. 

> It's also important to note that in security, most people specialize in just two or three areas. It’s virtually impossible to master _everything_, so don't stress about becoming an expert in every area and just focus on building a solid foundation and continuously growing your expertise in your areas of interest.
 
With all of that aside, in the following section, I list a bunch of technical skills that I believe are the __most__ beneficial to becoming a pentester (and are in no particular order). You should opt to know at least Web Application and Network Pentesting to be of a junior level, and at least 3-4 of these skills to be at a senior level.

Along with each skill, I provide a short description of what you might be doing, followed by a list of resources that should be beneficial in either getting you started or in helping you learn more about the topic.

Now, before we dive-in, I know what a few of you might be saying right now... "_But Jack! These links are all related to offensive techniques. What about people who want to go into defensive security like SOC, Incident Response (IR), or Security Engineering?_"

While the skills and resources listed in the following section are primarily centered around offensive security (i.e., penetration testing), they are still incredibly valuable for those interested in defensive security roles. Understanding how attackers think and the tools they use is crucial for detecting, preventing, and responding to security incidents effectively. In fact, many of the concepts from offensive security, such as network hacking, web application vulnerabilities, and exploitation techniques, can help you better identify and mitigate potential threats in a defensive capacity.

For example, if you're working in a SOC, knowing how attackers gain access to systems can help you recognize suspicious behavior early on. Similarly, in Incident Response (IR), understanding attack vectors allows you to investigate and contain incidents more efficiently. Even in security engineering, having a solid grasp of how exploits work and how code vulnerabilities are exploited can guide you in designing systems that are more resilient to attacks.

In short, while your day-to-day tasks might differ, a foundational knowledge of offensive security will significantly enhance your ability to defend against cyber threats - so definitely utilize the links below to expand your skillset.

### 1. Web App Security:

Web Applications play a vital role in modern organizations today as more and more software applications are delivered to users via a web browser. Pretty much everything you might have done on the internet involves the use of a web application - whether that was to register for an event, buy items online, pay your bills, or even play games.

Due to the wide utilization of web apps, they are commonly the #1 most attacked asset on the internet and usually account for a wide range of compromises, such as [Panera Bread](https://krebsonsecurity.com/2018/04/panerabread-com-leaks-millions-of-customer-records/) and the [Equifax Breach](https://www.securityweek.com/equifax-confirms-apache-struts-flaw-used-hack).

Is it true that these breaches could have been prevented? Yes! But only if the web apps were thoroughly tested either internally or by a consulting firm. Yet even then - such vulnerabilities could have been missed.

Why might that be? Well, honestly it could have been a plethora of things such as unskilled testers, constrictive scope, too large of a scope, too little project time, too many web apps and not enough testers, no source code provided... the list goes on.

Though in the end, a skilled tester who understands web apps, how they function, communicate, what libraries they utilize, etc., can easily spot portions of a web app that might seem vulnerable or interesting to an attacker. Will the tester be able to spot everything? No, of course not - we aren't superhuman, but with experience and a good breadth of knowledge you'll be able to find enough vulnerabilities that will most likely secure a web app from future attacks.

As a penetration tester, you'll be testing the security of a wide range of online platforms, such as banking applications, ecommerce websites, cloud hosting services, and more. To do this effectively you’ll need to go beyond the basic web application vulnerabilities like Cross-Site Scripting (XSS), SQL Injection (SQLi), and Cross-Site Request Forgery (CSRF). You'll also need to be familiar with more advanced vulnerabilities, including XML External Entity (XXE) attacks, XML and JSON injection, LDAP injection, and blind injections. Other important issues include code and template injection, subdomain takeovers, open redirects, Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and Remote File Inclusion (RFI) to name a few.

Additionally, understanding key protocols and how they’re implemented such as  [OAuth](https://oauth.net/2/), and [SSO](https://en.wikipedia.org/wiki/Single_sign-on) will be crucial. Familiarity with the security challenges specific to certain platforms, like GitHub, Jenkins and Elasticsearch, is also vital for identifying potential vulnerabilities.

To add on to that, it also helps understanding the language the web app is built on, since a ton of web assessments are at times paired with code reviews. Knowing languages such as Java, JavaScript, Scala, PHP or ASP.NET will really help spot those hidden gems that might not come up in a [black box](https://en.wikipedia.org/wiki/Black-box_testing) assessment.

If you're currently sitting here and freaking out after reading all of that... don't! It sounds way more complicated in person then it really is. Just take the time to learn the basics, and everything else will come with practice and experience!

__Resources__:  Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

- [Apps for Testing & Practice](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=Main)
- [Awesome CI/CD Attacks](https://github.com/TupleType/awesome-cicd-attacks)
- [Awesome Web Hacking](https://github.com/infoslack/awesome-web-hacking)
- [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security)
- [Bug Bounty Bootcamp: The Guide to Finding and Reporting Web Vulnerabilities](https://nostarch.com/bug-bounty-bootcamp)
- [Bug Bounty Reference](https://github.com/ngalongc/bug-bounty-reference)
- [Detectify Security Blog](https://labs.detectify.com/)
- [Hacker 101](https://www.hacker101.com/)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity?sort_type=latest_disclosable_activity_at&filter=type%3Apublic&page=1)
- [Hacking APIs: Breaking Web Application Programming Interfaces](https://nostarch.com/hacking-apis)
- [HackTheBox Academy: Bug Bounty Hunter](https://academy.hackthebox.com/path/preview/bug-bounty-hunterr)
- [HackTheBox Academy: Senior Web Penetration Tester](https://academy.hackthebox.com/path/preview/senior-web-penetration-tester)
- [InfoSec Write-Ups: Bug Bounty](https://infosecwriteups.com/tagged/bug-bounty)
- [James Kettle / albinowax Research](https://skeletonscribe.net/)
- [LiveOverflow: Web Hacking Video Series](https://www.youtube.com/watch?v=jmgsgjPn1vs&list=PLhixgUqwRTjx2BmNF5-GddyqZcizwLLGP)
- [OWASP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
- [OWASP WAPT Testing Guide](https://www.owasp.org/index.php/Web_Application_Penetration_Testing)
- [PentesterLab Bootcamp](https://pentesterlab.com/bootcamp)
- [PentesterLand: Bug Bounty Writeups](https://pentester.land/writeups/)
- [PortSwigger Research](https://portswigger.net/research)
- [PortSwigger: WebSecurity Academy](https://portswigger.net/web-security)
- [Real-World Bug Hunting: A Field Guide to Web Hacking](https://nostarch.com/bughunting)
- [SANS 2016 Holiday Hack Challenge](https://jhalon.github.io/sans-2016-holiday-hack-challenge/)
- [Source Incite Blog](https://srcincite.io/blog/)
- [Stanford CS253: Web Security](https://web.stanford.edu/class/cs253/)
- [TryHackMe: DevSecOps](https://tryhackme.com/r/path/outline/devsecops)
- [TryHackMe: Web Fundamental](https://tryhackme.com/r/path/outline/web)
- [TryHackMe: Web Application Pentesting](https://tryhackme.com/r/path/outline/webapppentesting)
- [The Tangled Web: A Guide to Securing Modern Web Applications](https://www.amazon.com/Tangled-Web-Securing-Modern-Applications/dp/1593273886)
- [The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws](https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470)
- [Youtube: PwnFunction](https://www.youtube.com/@PwnFunction/videos)
- [Youtube: STOK](https://www.youtube.com/@STOKfredrik/videos)

### 2. Network Security:

A Network Pentest aims to identify and exploit vulnerabilities in corporate or industrial networks as well as in network devices and the hosts/systems connected to them. Such assessments usually simulate a real-world attack if a hacker was to gain access to the internal network of a company.

Now, can a network be 100% safe and secure? Of course not! Nothing is 100% secure! For example, let's take the [Hacking Team Breach](https://web.archive.org/web/20160417195320/https://ghostbin.com/paste/6kho7). Any sophisticated attacker with enough time, money, and resources can breach a company; but that doesn't mean it should be easy for them once they are inside the network!

Another example would be of the [NotPetya](https://www.theregister.co.uk/2017/06/28/petya_notpetya_ransomware/) Malware breakout in Ukraine. This is a great example of how hackers with enough time and resources can compromise a company and utilize them to further carry out more attacks against other targets.

As a pentester you will be tasked with trying to assess the risk of a potential security breach, which isn't just about gaining high-level access, like becoming a Domain Admin, but about identifying and evaluating what kind of proprietary data is unprotected and out in the open.

During your assessment, you'll look for areas where sensitive information could be compromised. Are user accounts and credentials stored securely, or are they easily accessible? Can customer data such as credit card information be found with minimal effort? How well-trained are employees in spotting common security threats like phishing? Are security technologies properly configured and functioning? And more!

To be able to carry out a Network Pentest you need a deep understanding of how networks operate. You should be familiar with networking technologies and communication protocols like TCP/IP, LDAP, SNMP, SMB, and VoIP to name a few. You’ll also need to understand enterprise technologies like Active Directory and how they manage user access and permissions since identifying misconfigurations is a critical part of network pentesting, like poorly configured access control lists (ACLs), and open file shares that could expose sensitive data. You need to also understand how Windows and Linux internals function, and how you can utilize them to further compromise other users and host systems.

While Network Pentests are complex and require a lot of moving parts, they aren't too complex to learn about. Once you learn and understand the basic knowledge of how Active Directory works and how to move around the network, the rest comes with experience - just like everything else!

__Resources__: Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

- [Active Directory Kill Chain Attack & Defense](https://github.com/infosecn1nja/AD-Attack-Defense)
- [AD Security](https://adsecurity.org/)
- [Adversarial Tactics, Techniques & Common Knowledge](https://attack.mitre.org/wiki/Main_Page)
- [Awesome Pentest](https://github.com/enaqx/awesome-pentest)
- [Awesome Red Teaming](https://github.com/0xMrNiko/Awesome-Red-Teaming)
- [Bad Sector Labs: Last Week In Security](https://blog.badsectorlabs.com/)
- [HackTheBox Academy: Active Directory Enumeration](https://academy.hackthebox.com/path/preview/active-directory-enumeration)
- [HackTheBox Academy: Active Directory Penetration Tester](https://academy.hackthebox.com/path/preview/active-directory-penetration-tester)
- [HackTricks: Pentesting Networks](https://book.hacktricks.wiki/en/index.html)
- [harmj0y Blogs](https://blog.harmj0y.net/blog/)
- [Hausec: Domain Penetration Testing Series](https://hausec.com/domain-penetration-testing/)
- [Infrastructure Pentest Series](https://bitvijays.github.io/index.html)
- [IppSec's Videos](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA)
- [Metasploitable](https://information.rapid7.com/download-metasploitable-2017.html)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
- [Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/)
- [Pen Test Partners Blog](https://www.pentestpartners.com/security-blog/)
- [Penetration Testing Lab](https://pentestlab.blog/)
- [Pentestit Lab Writeups](https://jhalon.github.io/categories.html)
- [Red Team Notes](https://www.ired.team/)
- [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)
- [SANS Penetration Testing Blog](https://www.sans.org/blog/?focus-area=offensive-operations
- [SpecterOps: BloodHound Blogs](https://posts.specterops.io/bloodhound/home)
- [SpecterOps: Blog](https://specterops.io/blog/)
- [SpecterOps YouTube Videos](https://www.youtube.com/@specterops/videos)
- [The Hacker Playbook 3: Practical Guide To Penetration Testing](https://www.amazon.com/Hacker-Playbook-Practical-Penetration-Testing-ebook/dp/B07CSPFYZ2)
- [TryHackMe: Hacking Active Directory](https://tryhackme.com/module/hacking-active-directory)
- [TryHackMe: Red Teaming](https://tryhackme.com/r/path/outline/redteaming)
- [Windows APIs](https://docs.microsoft.com/en-us/windows/desktop/apiindex/windows-api-list)
- [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
- [ZeroSec: Paving the Way to DA](https://blog.zsec.uk/paving-2-da-wholeset/)
- Google... Just too much to list!

### 3. Code Review:

Code review is probably the most effective method for identifying vulnerabilities and misconfigurations in applications. By manually reviewing the source code, and combining it with automated and manual testing tools, you can uncover flaws that might not be easily detected during a traditional black box penetration test. These include complex issues like logic flaws, improper authorization controls, encryption misconfigurations, and even vulnerabilities like second hand injection attacks.

The only downside to Code Review is that it can be extremely time consuming, and if the application is large or complex, a single tester may struggle to review the entire codebase thoroughly. To combat this, a tester typically focus on high-risk areas, such as known vulnerable functions that are commonly associated with security issues. For example, in C we know that the [strcpy()](https://www.tutorialspoint.com/c_standard_library/c_function_strcpy.htm) function is known to be vulnerable to buffer overflows, or in PHP, the [exec()](http://php.net/manual/en/function.exec.php) function if not properly utilized can lead to Remote Code Execution.

If it wasn't for code reviews then some of the most prolific bugs like [Heartbleed](http://heartbleed.com/), [Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)), [Drupalgeddon 2](https://research.checkpoint.com/uncovering-drupalgeddon-2/), etc. would have never been found, so it goes to show how important code review can be!

As a pentester you will probably be reviewing a lot of applications built using C, C++, Java, JavaScript, .NET, Ruby, PHP, Python, and even Go. To be able to thoroughly review the application and find vulnerabilities or security issues you need to have a decent understanding of the underlying language and the issues that might arise.

Do note that some vulnerabilities are more prevalent in only certain languages. For example, buffer overflow are more prevalent in lower-level languages like C and C++, where memory management is done manually. In contrast, languages like Python and .NET are higher-level languages and generally handle memory management automatically via a garbage collector, making such issues less likely. On the other hand, vulnerabilities like [deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet) are often found in languages like Python, Java, and .NET, where object data is commonly serialized and deserialized, but are less common in C and C++.

So, all in all, it's a really good idea to learn a programming language as it will immensely help in your career toward becoming a pentester. Not only will it help you understand how specific vulnerabilities arise in source code, but it will also enable you to write scripts and build exploits that can be used during penetration tests. Whether you’re developing a Proof of Concept (PoC) to demonstrate a vulnerability or quickly creating a fuzzer to test an application, programming knowledge is a powerful tool in your pentester toolkit.

__Resources__: Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

- [24 Deadly Sins of Software Security: Programming Flaws and How to Fix Them](https://www.amazon.com/Deadly-Sins-Software-Security-Programming/dp/0071626751)
- [Awesome AppSec](https://github.com/paragonie/awesome-appsec)
- [Awesome Code Review](https://github.com/joho/awesome-code-review)
- [Awesome Static Analysis](https://github.com/mre/awesome-static-analysis)
- [Codecademy](https://www.codecademy.com/)
- [Designing Secure Software](https://nostarch.com/designing-secure-software)
- [GitLab Security Secure Coding Training](https://handbook.gitlab.com/handbook/security/secure-coding-training/)
- [Kontar AppSec: Front-End Top 5](https://application.security/free/kontra-front-end-top-5)
- [Kontar AppSec: OWASP Top 10 API](https://application.security/free/owasp-top-10-API)
- [Kontar AppSec: OWASP Top 10](https://application.security/free/owasp-top-10)
- [Open Security: Secure Code Review Guide](https://opensecuritytraining.info/SecureCodeReview.html)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf)
- [OWASP Code Review Project](https://www.owasp.org/index.php/Category:OWASP_Code_Review_Project)
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
- [Secure Coding Dojo](https://owasp.org/SecureCodingDojo/codereview101/)
- [Static Code Analysis Tools](https://github.com/codefactor-io/awesome-static-analysis)
- [Synk: Developer Security Training](https://learn.snyk.io/)
- [Snyk Vulnerability Database](https://security.snyk.io/)
- [The Art of Software Security Assessment: Identifying and Preventing Software Vulnerabilities](https://www.amazon.com/Art-Software-Security-Assessment-Vulnerabilities/dp/0321444426)
- [Vulnerabilities 1001: C-Family Software Implementation Vulnerabilities](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Vulns1001_C-family+2023_v1/about)
- [Vulnerabilities 1002: C-Family Software Implementation Vulnerabilities](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Vulns1002_C-family+2023_v1/about)
- [CodeQL Zero to Hero Part 1: The Fundamentals of Static Analysis for Vulnerability Research](https://github.blog/2023-03-31-codeql-zero-to-hero-part-1-the-fundamentals-of-static-analysis-for-vulnerability-research/)
- Reading the Languages Docs
- Google... like seriously guys!

### 4. Binary Reverse Engineering / Exploit Development:

Ahh yes, Reverse Engineering, the unexplained phenomena where a hacker reads some weird ancient language and for some magical reason creates an exploit or understands how the application functions.... Okay, maybe not really magical, and not an ancient language too!

Binary Reverse Engineering is the process of disassembling and analyzing an application to understand how it works in order to either exploit it, or to find specific vulnerabilities. This practice is now frequently utilized by Red Teamers or Exploit Developers when looking for 0days, or during engagements in certain industries, or even when source code isn't provided. Through reverse engineering one can reveal how an application performs certain operations, handles data, or writes to memory, often using tools like [IDA Pro](https://www.hex-rays.com/products/ida/), [Binary Ninja](https://binary.ninja/), and [Ghidra](https://ghidra-sre.org/).

A common misconception is that reverse engineering is only associated with malware analysis, such as in the [WannaCry Malware](https://www.endgame.com/blog/technical-blog/wcrywanacry-ransomware-technical-analysis) to fully understand how the malware functions, but that's really not the case! Malware is essentially just another application, and the process of reverse engineering it is no different than analyzing any other program, in the end you're still reversing an application... just a malicious one.

Take this for example, the [1-day exploit development for Cisco IOS](https://media.ccc.de/v/34c3-8936-1-day_exploit_development_for_cisco_ios) used reverse engineering and debugging to exploit a vulnerability in Cisco Routers, something that can't be done through simple fuzzing or black box pentesting.

As a penetester, having a basic understanding of reverse engineering and exploit development will likely be beneficial, especially for engagements that require advanced research. You'll use these skills to understand how applications functions when source code is not provided, which is particularly useful when working with embedded systems or hardware devices. You may also find yourself dealing with more complex targets like BIOS/SMM, virtualization environments, containers, secure boot processes, and more.

To excel in these tasks, you'll need a solid grasp of assembly languages for both x86 and x64 architectures, possibly MIPS too, along with a deep understanding of how the stack, heap, and memory allocation work. Additionally, knowledge of low-level operating system internals is extremely helpful for tackling these types of challenges.

While the learning curve for this specialty is usually very high, and it does take some time to be proficient in it - but once you've mastered it, it can be considered as a nuclear bomb in your arsenal. You can then officially call yourself a full-fledged hakzor! Additionally, this expertise can open up new career paths that allow you to transition into roles such as  Security Research or Malware Reverse Engineering.

__Resources__: Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

- [Architecture 1001: x86-64 Assembly](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch1001_x86-64_Asm+2021_v1/about)
- [Architecture 2001: x86-64 OS Internals](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Arch2001_x86-64_OS_Internals+2021_v1/about)
- [Awesome Reversing](https://github.com/ReversingID/Awesome-Reversing)
- [COMPSCI 390R: Reverse Engineering & Vulnerability Analysis](https://pwn.umasscybersec.org/index.html)
- [CrackMe Challanges](https://crackmes.one/)
- [Debuggers 1011: Introductory WinDbg](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1011_WinDbg1+2021_v1/about)
- [Debuggers 1012: Introductory GDB](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1012_GDB_1+2021_v1/about)
- [Debuggers 1101: Introductory IDA](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1101_IntroIDA+2024_v1/about)
- [Debuggers 1102: Introductory Ghidra](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg1102_IntroGhidra+2024_v2/about)
- [Debuggers 2011: Intermediate WinDbg](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Dbg2011_WinDbg2+2021_v1/about)
- [Diary of a Reverse Engineer](https://doar-e.github.io/)
- [Exploit Club Blog](https://blog.exploits.club/)
- [Exploit Education](https://exploit.education/)
- [Exploit Exercises](https://exploit-exercises.com/)
- [FuzzySec - Part 1: Introduction to Exploit Development](https://fuzzysecurity.com/tutorials/expDev/1.html)
- [Getting Started with Reverse Engineering](https://jlospinoso.github.io/developing/software/software%20engineering/reverse%20engineering/assembly/2015/03/06/reversing-with-ida.html)
- [GitHub: Awesome Reversing](https://github.com/ReversingID/Awesome-Reversing)
- [GitHub: Fuzzing-101](https://github.com/antonio-morales/Fuzzing101)
- [GitHub: Fuzzing Lab (ACM Cyber)](https://github.com/pbrucla/fuzzing-lab)
- [Guided Hacking: Game Hacking Forum](https://guidedhacking.com/)
- [HackDay:  LEARN TO REVERSE ENGINEER X86_64 BINARIES](https://hackaday.com/2018/01/06/getting-acquainted-with-x86_64-binaries/)
- [Hacking, The Art of Exploitation 2nd Edition](https://nostarch.com/hacking2.htm)
- [Hasherezade: How to Start RE/Malware Analysis](https://hshrzd.wordpress.com/how-to-start/)
- [IDA Pro Book, 2nd Edition](https://nostarch.com/idapro2.htm)
- [Introduction to Reverse Engineering with Ghidra](https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra)
- [Introduction To Reverse Engineering Software](http://opensecuritytraining.info/IntroductionToReverseEngineering.html)
- [Introduction To Software Exploits](http://www.opensecuritytraining.info/Exploits1.html)
- [Introductory Intel x86-64: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntroX86-64.html)
- [Introductory Intel x86: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntroX86.html)
- [LiveOverflow Videos](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w/videos)
- [MalwareUnicorn: Workshops](https://malwareunicorn.org/#/workshops)
- [Nightmare: Into to Binary Exploitation](https://guyinatuxedo.github.io/index.html)
- [OALabs: Malware Reverse Engineering](https://www.youtube.com/@OALABS)
- [Off By One Secxurity: Vulnerability Research & Exploit Dev](https://www.youtube.com/@OffByOneSecurity)
- [Offensive Security & Reverse Engineering Course](https://exploitation.ashemery.com/)
- [0x00 Sec: Exploit Development](https://0x00sec.org/c/exploit-development/53)
- [0x00 Sec: Reverse Engineering](https://0x00sec.org/c/reverse-engineering/58)
- [Practical Binary Analysis](https://nostarch.com/binaryanalysis)
- [PWN College](https://pwn.college/)
- [RET2 Wargames](https://wargames.ret2.systems/)
- [POP Emporium: Learn ROP Exploit Development](https://ropemporium.com/index.html)
- [Reverse Engineering 3011: Reversing C++ Binaries](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+RE3011_re_cpp+2022_v1/about)
- [Reverse Engineering 3201: Symbolic Analysis](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+RE3201_symexec+2021_V1/about)
- [Reverse Engineering Resources](https://github.com/wtsxDev/reverse-engineering)
- [Secret Club: Reverse Engineering Blog](https://secret.club/)
- [The Shellcoder's Handbook: Discovering and Exploiting Security Holes](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X)
- [Unknown Cheats: Game Hacking Forum](https://www.unknowncheats.me/forum/index.php)
- [wtsxDev - Reverse Engineering Resources](https://github.com/wtsxDev/reverse-engineering)
- Oh look.... Google!

### 5. Hardware/Embedded Devices Security:

Following closely in the footsteps of Reverse Engineering is the world of Hardware and Embedded Device security. With a solid understanding of hardware, electronics, and ARM architecture, you’ll find yourself in demand for roles that involve dissecting everything from routers and smart devices to lightbulbs and even cars.

With the increase in the development of IoT devices there is now a raised interest and controversy about the security of such systems. Let's take the [Mirai Malware](https://krebsonsecurity.com/2016/10/who-makes-the-iot-things-under-attack/) as an example, which exploited insecure devices that were easily accessible on the internet. With a ton of insecure devices open on the internet, a company is simply one device away from a breach. Yah, just one device, for example when a [casino got hacked through its internet connected fish tank](https://thehackernews.com/2018/04/iot-hacking-thermometer.html).

Embedded systems are everywhere, from everyday household items to industrial machines. These systems typically run on [microcontrollers](https://en.wikipedia.org/wiki/Microcontroller), which means that some knowledge of computer and electronics is essential.

As a pentester, if you're doing any hardware or embedded device security, you'll need to become familiar with concepts such as [SPI](https://en.wikipedia.org/wiki/Serial_Peripheral_Interface), reading [schematics](https://en.wikipedia.org/wiki/Schematic), [FPGA](https://en.wikipedia.org/wiki/Field-programmable_gate_array), [UART](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver-transmitter), and [JTAG](https://en.wikipedia.org/wiki/JTAG). Understanding how to use tools like a [multimeter](https://en.wikipedia.org/wiki/Multimeter) and a [soldering iron](https://en.wikipedia.org/wiki/Soldering_iron) will be crucial for tasks like probing circuits or reworking hardware. It’s also helpful to have a good understanding of basic electronic components such as resistors, capacitors, switches, and transistors.

Also knowing the x86/x64 ASM, MIPS, and [ARM](https://en.wikipedia.org/wiki/ARM_architecture) architectures will greatly enhance your ability in testing such devices. Once you can extract the system image from [flash memory](https://en.wikipedia.org/wiki/Flash_memory) or gain access to the source code, you’ll be able to uncover vulnerabilities or exploit weaknesses.

Just like Reverse Engineering, the learning curve for embedded device security can be steep. However, once you grasp the basics everything starts to fall into place, and your expertise grows through hands-on experience. Honestly the best way to learn is by jumping into the fire and learning as you go.

__Resources__: Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

- [Awesome Embedded and IoT Security](https://github.com/fkie-cad/awesome-embedded-and-iot-security)
- [Azeria Labs - ARM Tutorials](https://azeria-labs.com/)
- [Car Hackers Handbook: A Guide for the Penetration Tester](https://nostarch.com/carhacking)
- [Coursera: Introduction to the Internet of Things and Embedded System](https://www.coursera.org/learn/iot)
- [DEF CON 24 Internet of Things Village: Reversing and Exploiting Embedded Devices](https://www.youtube.com/watch?v=r4XntiyXMnA)
- [EEVBlog Videos](https://www.youtube.com/user/EEVblog/videos)
- [Exploit: Hands On IoT Hacking EBook](https://store.expliot.io/products/hands-on-internet-of-things-hacking)
- [Flashback Team: Extracting Firmware from Embedded Devices](https://www.youtube.com/watch?v=nruUuDalNR0)
- [GreatScott! Videos - Awesome Electronics Tutorials, Projects and How To's](https://www.youtube.com/user/greatscottlab)
- [Hackaday Hardware Hacking](https://hackaday.com/tag/hardware-hacking/)
- [HardBreak: Hardware Hacking Wiki](https://www.hardbreak.wiki/)
- [Hardware 1101: Intel SPI Analysis](https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+hw1101_intel_spi+2023_v1/about)
- [How to Read a Schematic](https://learn.sparkfun.com/tutorials/how-to-read-a-schematic)
- [Introduction to ARM](https://opensecuritytraining.info/IntroARM.html)
- [Introduction To Basic Electronics](https://www.makerspaces.com/basic-electronics/)
- [IoT Security 101](https://github.com/V33RU/IoTSecurity101)
- [LiveOverflow Videos - Riscure Embedded Hardware CTF](https://www.youtube.com/playlist?list=PLhixgUqwRTjwNaT40TqIIagv3b4_bfB7M)
- [Matt Brown YouTube Videos](https://www.youtube.com/@mattbrwn/videos)
- [Micro Corruption Embedded CTF](https://microcorruption.com/)
- [Microcontroller Exploits](https://nostarch.com/microcontroller-exploits)
- [OWASP Internet Of Things](https://owasp.org/www-project-internet-of-things/)
- [Practical Firmware Reversing and Exploit Development for AVR-based Embedded Devices](https://github.com/radareorg/radareorg/blob/master/source/_files/avrworkshops2016.pdf)
- [Practical IoT Hacking](https://nostarch.com/practical-iot-hacking)
- [Rapid7: Hands-On IoT Hacking](https://www.rapid7.com/globalassets/_pdfs/final-hands-on-iot-whitepaper-.pdf)
- [Reading Silicon: How to Reverse Engineer Integrated Circuits](https://www.youtube.com/watch?v=aHx-XUA6f9g)
- [Reverse Engineering Flash Memory for Fun and Benefit](https://www.blackhat.com/docs/us-14/materials/us-14-Oh-Reverse-Engineering-Flash-Memory-For-Fun-And-Benefit-WP.pdf)
- [Reverse Engineering Hardware of Embedded Devices](https://www.sec-consult.com/en/blog/2017/07/reverse-engineering-hardware-of-embedded-devices-from-china-to-the-world/)
- [Rhyme-2016 Hardware Hacking Challange](https://github.com/Riscure/Rhme-2016)
- [The Hardware Hacking Handbook](https://nostarch.com/hardwarehacking)
- [VoidStar Security Research Blog](https://voidstarsec.com/blog/)
- [WrongBaud Blog](https://wrongbaud.github.io/)
- Google.... Like I shouldn't even have to mention this!

### 6. Physical Security:

You can have the most advanced security systems, the most hardened infrastructure, and the best security team in the world, but none of that matters if an attacker can simply carry out your servers through the front door. This is where Physical Security comes in!

It's something unheard of, hackers breaking into companies... through the FRONT DOOR! \**[dun dun duuuunnnn](https://www.youtube.com/watch?v=cphNpqKpKc4)\** Yah, scary, I know! 

But honestly, really take a second to assess this matter. We spend so much time and resources securing our computer systems, web applications, and networks, but we often overlook the vulnerability that comes from the human and physical aspects. Anyone can just walk right into a company that has improper security controls and steal data, plant malware, or even carry out destructive actions.

As a pentester conducting a physical security assessment, you’ll need to understand a wide range of subjects. This includes everything from the psychology of human behavior, surveillance techniques, and lock picking to RFID security, camera systems, and universal keys. During a general assessment, you’ll typically survey the physical location, identify entry and exit points, and evaluate the effectiveness of existing security measures, such as guards, cameras, pressure sensors, motion detectors, and tailgating defenses.

After that you'll be required to break into the building via methods like lock picking (if in scope), tailgating, destructive entry (rarely in scope...) and even social engineering. Once inside you will be required to carry out certain objectives likes stealing a laptop, or connecting a [dropbox](https://www.blackhillsinfosec.com/how-to-build-your-own-penetration-testing-drop-box/), to even sitting at someone’s desk - like the CEO's!

It's almost as if you were a full-fledged spy! While this may sound exciting, it's actually quite challenging to execute. You need a solid understanding of human psychology, body language, and social cues, and understand how different locks and security mechanisms work. If you're not good with people, or get really nervous when lying, then maybe this isn't for you, but it’s still worth learning and can be a valuable skill to have! 

__Resources__: Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

> **NOTE**: Please note, that some of the materials in here, including the psychological resources for manipulation can be rather offensive and insensitive. I do not condone any of these activities to be used for bad, only for good. I'm also not responsible for the misuse of this information.

- [10 Psychological Studies That Will Boost Your Social Life](https://thequintessentialmind.com/10-psychological-studies-that-will-boost-your-social-life/)
- [Awesome Lockpicking](https://github.com/meitar/awesome-lockpicking)
- [Awesome Physical Security](https://github.com/rustrose/awesome-physec)
- [Body Language vs. Micro-Expressions](https://t.co/PSOFkCLJgL)
- [CONFidence 2018: A 2018 practical guide to hacking RFID/NFC (Sławomir Jasek)](https://www.youtube.com/watch?v=7GFhgv5jfZk)
- [Deviant Ollam Youtube](https://www.youtube.com/user/DeviantOllam/videos)
- [Lock Bypass](http://www.lockwiki.com/index.php/Bypass)
- [Lock Wiki](http://www.lockwiki.com/index.php/Main_Page)
- [Lockpicking - by Deviant Ollam](https://deviating.net/lockpicking/presentations.html)
- [Lockpicking 101](https://www.itstactical.com/skillcom/lock-picking/lock-picking-101/)
- [Locksport: A Hacker’s Guide to Lockpicking, Impressioning, and Safe Cracking](https://nostarch.com/locksport)
- [Practical Social Engineering](https://nostarch.com/practical-social-engineering)
- [Psychological Manipulation Wiki](https://en.m.wikipedia.org/wiki/Psychological_manipulation)
- [Red Team: How to Succeed By Thinking Like the Enemy](https://www.amazon.com/Red-Team-Succeed-Thinking-Enemy/dp/1501274899)
- [RFID Cloning](https://www.getkisi.com/blog/how-to-copy-access-cards-and-keyfobs)
- [The Dictionary of Body Language: A Field Guide to Human Behavior](https://www.amazon.com/Dictionary-Body-Language-Field-Behavior-ebook/dp/B075JDX981)
- [The Ethics of Manipulation](https://plato.stanford.edu/entries/ethics-manipulation/)
- [TOOOL: The Open Organisation Of Lockpickers](https://toool.us/)
- [UFMCS, "The Applied Critical Thinking Handbook"](https://fas.org/irp/doddir/army/critthink.pdf)
- [Unauthorised Access: Physical Penetration Testing For IT Security Teams](https://www.amazon.com/Unauthorised-Access-Physical-Penetration-Security/dp/0470747617)
- [What Every Body Is Saying: An Ex-FBI Agent's Guide to Speed-Reading People](https://www.amazon.com/What-Every-Body-Saying-Speed-Reading/dp/0061438294)
- [Youtube: LockPickingLawyer](https://www.youtube.com/c/lockpickinglawyer/videos)
- Lockpicking Village at Hacker Conferences!
- Google & YouTube...

### 7. Cloud Security:

You hear it pretty much every day, another data breach, all thanks to a [misconfigured S3 Bucket](https://businessinsights.bitdefender.com/worst-amazon-breaches)! With the rapid adoption of cloud services, you’d think security would have kept pace, but unfortunately that’s not always the case.

Cloud platforms like AWS, Azure, and Google Cloud have become incredibly popular, and many companies are migrating or building new infrastructure "in the cloud" because it’s cost-effective and scalable. But just because something is easy to implement doesn’t mean it's easy to secure.

Unfortunately, many developers, engineers, and even security professionals don’t fully understand the intricacies of cloud security, especially when it comes to configuring services correctly. Securing cloud environments is complex, and if you don’t take the time to properly configure your environment from the start, a lot can go wrong.

For example, a simple [SSRF](https://www.owasp.org/index.php/Server_Side_Request_Forgery) in a web app can lead to the compromise of the underlying cloud infrastructure. At the same time, misconfigured permissions or poorly managed Identity and Access Management (IAM) roles in something like AWS can allow attackers to gain unauthorized access to sensitive services, like cloud storage buckets, manipulate data, or even spin up new compute instances.

As a pentester, if you're focusing on cloud security, you’ll need a deep understanding of the cloud provider’s infrastructure like AWS, Azure, or GCP. You'll use this knowledge to assess configurations, such as ensuring user and group roles are appropriately assigned, verifying that storage buckets are secured, checking network security rules, and confirming that secure protocols and encryption practices are implemented throughout the environment.

At first this might seem like a daunting task, but in reality, once you understand how the general cloud infrastructure is laid out and how everything talks to each other, then securing it won't be too difficult. Again, it all comes with time and experience.

__Resources__: Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

- [AAD Internals](https://aadinternals.com/)
- [Awesome AWS Security](https://github.com/jassics/awesome-aws-security)
- [Awesome Azure Penetration Testing](https://github.com/Kyuu-Ji/Awesome-Azure-Pentest)
- [AWS Certified Security - Specialty](https://aws.amazon.com/certification/certified-security-specialty/)
- [AWS Certified Solutions Architect - Associate](https://aws.amazon.com/certification/certified-solutions-architect-associate/)
- [AWS Cloud Security](https://aws.amazon.com/security/)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/?cards-all.sort-by=item.additionalFields.sortDate&cards-all.sort-order=desc&awsf.content-type=*all&awsf.methodology=*all)
- [AWS Security Learning](https://aws.amazon.com/security/security-resources/)
- [AWS Vulnerabilities and the Attacker’s Perspective](https://rhinosecuritylabs.com/cloud-security/aws-security-vulnerabilities-perspective/)
- [AzureGoat: A Damn Vulnerable Azure Infrastructure](https://github.com/ine-labs/AzureGoat?ref=thezentester.com)
- [BadZure - Vulnerable Azure AD Lab](https://github.com/mvelazc0/BadZure?ref=thezentester.com)
- [BishopFox: CloudFoxable](https://cloudfoxable.bishopfox.com/)
- [Breaching the Cloud Perimeter](https://www.blackhillsinfosec.com/wp-content/uploads/2020/05/Breaching-the-Cloud-Perimeter-Slides.pdf)
- [Dirkjan: Azure Security Blogs](https://dirkjanm.io/)
- [Hacking Like a Ghost: Breaching the Cloud](https://nostarch.com/how-hack-ghost)
- [Hacking The Cloud Encyclopedia](https://hackingthe.cloud/)
- [HackTheBox: AWS Penetration Testing](https://www.hackthebox.com/blog/aws-pentesting-guide)
- [HackTricks Cloud](https://cloud.hacktricks.wiki/en/index.html)
- [Internal All The Things - Cloud](https://swisskyrepo.github.io/InternalAllTheThings/)
- [Pentesting Azure Applications](https://nostarch.com/azure)
- [PurpleCloud: Cyber Rank - Azure](https://www.purplecloud.network/?ref=thezentester.com)
- [Rhino Security Labs: CloudGoat ](https://github.com/RhinoSecurityLabs/cloudgoat?ref=thezentester.com)
- [ROADTools - Azure AD Interaction Framework](https://github.com/dirkjanm/ROADtools)
- [SpecterOps: Azure Blog Posts](https://posts.specterops.io/tagged/azure)
- [TryHackMe: Attacking and Defending AWS](https://resources.tryhackme.com/attacking-and-defending-aws)
- [XPN Blog](https://blog.xpnsec.com/)
- I'm not cloud focused... so use Google!

### 8. Mobile Security:

With the increasing reliance on smartphones, mobile devices have become prime targets for attackers. People store nearly everything on their phones - photos, documents, passwords, credit card details, and much more. By compromising someone’s phone, an attacker can gain access to all of their personal accounts and, essentially their entire life.

Take this headline for example, "[Millions of Android Devices are Vulnerable Right Out of the Box!](https://www.wired.com/story/android-smartphones-vulnerable-out-of-the-box/)" Crazy, right? Many of us think that companies such as Google and Apple would make sure that their stuff was secure, that is until we see another headline such as "[Google Fixes Critical Android Vulnerabilities](https://www.securityweek.com/google-fixes-critical-android-vulnerabilities)"... lovely.

From vulnerabilities like Android’s [StageFright](https://www.androidcentral.com/stagefright) to Apple’s [ImageIO](https://nakedsecurity.sophos.com/2016/07/20/update-now-macs-and-iphones-have-a-stagefright-style-bug/) exploit, to issues in third-party components like [Qualcomm](https://www.cvedetails.com/vulnerability-list/vendor_id-153/Qualcomm.html), the attack surface is vast. These vulnerabilities can affect even the most secure users, making mobile security a high priority for researchers, vendors, and organizations. As an example, [Pegasus](https://en.wikipedia.org/wiki/Pegasus_(spyware)) takes the cake and details how mobile vulnerabilities can be abused for all the wrong reasons. As a result, mobile security is now a key part of the cybersecurity landscape, with increasing attention to mobile apps, mobile operating systems, and the hardware itself.

As a pentester, if you're going to be doing Mobile Security then you'll need to understand ARM Architecture as that's what you'll be seeing a lot of when reverse engineering apps and the core OS. For Android it's best to learn and understand Java and the [Android Runtime](https://en.wikipedia.org/wiki/Android_Runtime), but for iOS you'll need to learn [Swift](https://developer.apple.com/swift/) and [Objective-C](https://en.wikipedia.org/wiki/Objective-C). 

Your daily tasks could include reverse engineering mobile apps, reviewing app source code, conducting mobile web application pentests, or even analyzing and securing the core mobile OS. Additionally, mobile security testing often extends to other parts of the phone, such as Bluetooth, Wi-Fi, SMS/MMS protocols, and more, all of which have their own unique attack vectors.

__Resources__: Below are a bunch of resources that should either (__A__) help you get started or (__B__) help advance your knowledge!

- [Android Hacker's Handbook](https://www.amazon.com/Android-Hackers-Handbook-Joshua-Drake/dp/111860864X/ref=dp_rm_img_1)
- [Android Hacking 101](https://github.com/Devang-Solanki/android-hacking-101)
- [Android Security Internals: An In-Depth Guide to Android's Security Architecture](https://www.amazon.com/Android-Security-Internals-Depth-Architecture/dp/1593275811)
- [Android App Reverse Engineering 101](https://www.ragingrock.com/AndroidAppRE/)
- [Awesome Mobile Security](https://github.com/vaib25vicky/awesome-mobile-security)
- [Azeria Labs - ARM Tutorials](https://azeria-labs.com/)
- [BugCrowd: Mobile Hacking Resource Kit](https://www.bugcrowd.com/wp-content/uploads/2023/12/mobile-hacking-resource-kit.pdf)
- [Corellium: Hunting for Vulnerabilities in iOS Apps](https://www.corellium.com/hunting-ios-vulnerabilities)
- [Corellium: Mobile Security Training](https://www.corellium.com/training)
- [Frida](https://frida.re/docs/home/)
- [Google: Android App Hacking Workshop](https://bughunters.google.com/learn/presentations/5783688075542528/android-app-hacking-workshop)
- [Hacker101: Mobile Hacking Crash Course](https://www.hacker101.com/playlists/mobile_hacking.html)
- [HackTheBox: Intro To Mobile Pentesting](https://www.hackthebox.com/blog/intro-to-mobile-pentesting)
- [iOS Application Security: The Definitive Guide for Hackers and Developers](https://www.amazon.com/iOS-Application-Security-Definitive-Developers/dp/159327601X)
- [iOS Hacker's Handbook](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123/ref=pd_lpo_sbs_14_t_2/140-2741177-2826762?_encoding=UTF8&psc=1&refRID=PZKSM7AHR73QPKTT4E31)
- [iOS Hacking Resources(https://github.com/Siguza/ios-resources)
- [iPhone Development Wiki](https://iphone-dev.com/)
- [Mobile Hacking Labs](https://www.mobilehackinglab.com/free-mobile-hacking-labs)
- [OWASP Mobile Application Security Testing Guide](https://mas.owasp.org/MASTG/)
- [Reverse Engineering iOS Apps - iOS 11 Edition (Part 1)](https://ivrodriguez.com/reverse-engineer-ios-apps-ios-11-edition-part1/)
- [The Mobile Application Hacker's Handbook](https://www.amazon.com/Mobile-Application-Hackers-Handbook/dp/1118958500)
- Google.

### 9. Coding Languages 

While knowing a programming language is not always a technical requirement in certain security roles, I personally believe that it's an incredibly valuable skill to have which can significantly enhance your effectiveness as a security professional - at the cost of your sanity of course. 

I've seen a lot of people say "_Well I work in security and never coded anything in my life! You don't need to know how to code to work in security!_". That's partially true, you can absolutely perform security tasks without coding. But let me ask you this question: *How does it feel to be heavily reliant on tools written by others?*

It must suck when those tools break or don’t quite do what you need them to, and without knowing the language you can’t even begin to troubleshoot or fix them. Wouldn’t it be great to have the ability to look under the hood and understand exactly how they work, so you can either fix bugs or enhance them to suit your needs?

Knowing how to code isn't just about finding vulnerabilities or writing exploits but it’s about being self-sufficient. When you're working with security tools, understanding the code behind them allows you to troubleshoot, fix bugs, and extend the tool to perform more functions that might not yet be implemented.

So, while coding may not be a strict requirement, it sure does make your life a lot easier, and it can help you stand out as someone who doesn't just _use_ tools, but can _create_ and _improve_ them.

So, which programming languages are the most beneficial to learn? That’s actually a tough question to answer and it’s one that sparks a lot of heated debates among people. In my personal opinion if you truly must know at least one language that can do it all, then have it be....

- **Python**: This is a go-to language for security professionals because of its simplicity and versatility. Whether you’re writing scripts to automate testing, developing custom exploits, or analyzing vulnerabilities, Python is essential. Honestly, most of the exploits or scripts you will see on GitHub have been written in Python - you can even build your own web servers with it!

Now, when it comes to more specialized areas like pentesting, offensive development, reverse engineering, etc., you’ll need to pick up an additional set of languages in addition to Python. The key is to pick the language that aligns with your goals and field of interest. You don’t need to learn every language out there, just focus on the ones that will help you the most in your chosen field:

- **Low-Level Systems & Reverse Engineering**: If you're diving into reverse engineering, vulnerability research, code review, or working with low-level systems, **C** (or **C++**) is crucial. These languages give you a deep understanding of how applications interact with operating systems and hardware. They're essential when reverse engineering binaries, or understanding certain vulnerabilities like buffer overflows.
- **Web Application Security**: For web app pentesting, you'll want to start with **PHP**. Many web applications are built using this language so understanding it will help you understand common web vulnerabilities. From there, dive into **JavaScript** since all web apps utilize it and it's crucial for analyzing client-side code, understanding how data is handled in the browser, or for identifying security flaws in web applications.
- **Windows Security & Offensive Development**: If your focus is on Windows based tools or offensive security development, learning **C#** and **C** is a great choice. C# is widely used in enterprise environments and is also commonly used in penetration testing tools for Windows like [GhostPack](https://github.com/ghostpack). Knowing C will also allow you to dive deeper into how tools interact with operating systems and is useful for when writing custom [BOF's](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm) for C2's.

Now, I know a small group of you might be asking "*What about Go vs Rust?*". Honestly, don't get me started on that one. Pick and choose whichever you want. Also, remember that it’s impossible to learn every language. Focus on mastering 2 or 3 languages that are most relevant to your career path, rather than trying to be a jack of all trades. You'll always be able to pick up additional languages down the line as needed.
## The Education:

Like in every job your education is important! But in the Information Security realm, experience speaks louder. This doesn't mean that a degree and certifications are not looked at, it just means that they aren't heavily used to measure a candidate’s actual skill.

Now before you decide to drop out of High School or College because you think it won't benefit you as much, take a few minutes to hear me out! While a degree or certifications might not always be the first thing employers look for during an interview, they are still highly valued by HR and Talent Acquisition teams. In fact, having a degree or relevant certifications can often be the key to getting your foot in the door, especially in larger organizations or more traditional roles. That said the importance of a formal education varies by company, so pursuing a degree can still be a good idea even if it’s not the only factor that determines your future.

However, it's also important to note that not everyone follows the same path. Many people have broken into cybersecurity without completing a college degree, relying instead on a high school diploma or GED. If you fall into this category, don’t worry! While your chances of getting hired might potentially be lower than for those with degrees, your experience and certifications will speak for themselves. You will just need to make sure that you can demonstrate your expertise through projects, contributions to open-source tools, CVE's, conference talks and even research... but more on that in the Experience section!

### 1. College Degree:

When it comes to choosing a college degree, what you study actually matters. Sure you can study Fine Arts or Finance and still work in the security field, but you're going to have to back that up with significant experience and certifications. Regardless, this section is geared toward those of you still in high school or about to enter college and are uncertain about what to study.

If working in security is your goal, I recommend focusing your major on a computer related field such as computer engineering, computer science, or information technology. Due to the fact that these degree programs will teach different things completely, it's going to be your responsibility to make sure to take classes that are interesting to you, are relevant in the field you want to work in, and have supplementing material which you can use to expand your skills.

So what should you study?

- __Computer Engineering__: Opt for this degree if you’re interested in the more technical and hardware oriented side of security. You’ll learn programming languages like C/C++ and Assembly, dive into electronics and circuit design, and explore topics like embedded systems, microprocessors, software engineering, and more. This is ideal for those who want to work on low-level security, focusing on both software and hardware.

- __Computer Science__: This is a great choice if you want a well-rounded foundation in software development and systems programming. You'll study languages like C/C++, Java, and Python, along with key topics like algorithms, memory management, networking, computer security, and cryptography. If you enjoy software development, low-level programming, and DevOps, this degree will (hopefully) give you a solid background for a career in cybersecurity, especially in areas like secure coding and vulnerability research.

- __Information Technology__: If you want to be more generalized and learn things such as Java, Python, SQL, databases, networks, Window and Unix administration, and be more high-level with focus on web applications and corporate technologies. Just do note that for this degree you will need to choose your classes wisely to focus on what you would like to do. For example, instead of taking database management take a class on cyber security or computer engineering.

So, will a college education teach you everything that you need to know? No! Far from it! Think of college as a stepping stone into your career. While it can provide you with a lot of knowledge and the basics, the real learning comes from what you do beyond the classroom. As such, you need to take initiative and supplement what you learn with additional resources, hands-on practice, and continuous self-improvement.

This means that when you come home from school, do your homework, study for the exams you need, and then go learn something new by reading books, watching videos, practicing in labs, messing with hardware or trying to find an internship to be more hands on and involved in your education process. Learning in security doesn’t stop at the end of your classes or work day; it’s a lifelong process.

The 4 years you spend in college working toward your degree can either make you or break you... I'm being 100% serious! From my experience teaching graduate-level courses and mentoring students, I always notice that over 90% of the students don't even understand the basics. This just goes to show that you really need to be passionate about your future career and that you have to spend time outside of the classroom teaching yourself, because in all honesty, no one else will.

You need to be a self-starter, be motivated, and be willing to sacrifice your free time to actually become somebody. This is where the additional learning, certifications, and training comes into play. By going above and beyond, you’ll set yourself apart and build the expertise that’s necessary to thrive in cybersecurity.

Finally, I want to provide resources for those who might not be doing a college degree. CISA offers a plethora of cybersecurity education and training resources including K-12 and collegiate level programs, scholarship information, training courses, and more. I suggest checking out the following web page if you want to access to more resources not listed in this post.

- [NICSS: National Initiative for Cybersecurity Careers and Studies](https://niccs.cisa.gov/education-training)

### 2. Certifications:

Certifications are a great addition to your resume and show a potential employer that you can learn and retain information about certain topics. A well chosen certification not only validates your current skill but also proves that you're capable of mastering complex concepts. Whether it's a foundational certification like CompTIA Security+ or something more advanced like the Offensive Security Certified Professional (OSCP+), these credentials can set you apart from other candidates, especially when you’re just starting out or looking to transition into a new area of cybersecurity.

Just make sure that when you're doing a certificate, it's with the intention of genuinely learning the material, and not just trying to collect a few additional letters after your name. Many people make the mistake of chasing certifications as a shortcut to land a job or boost their credibility without taking the time to truly understand the subject matter. I'm looking at you OSCP cheaters!

At the same time be selective and careful about the certifications you pursue. Take into consideration their reputation, their [benefit-cost ratio](https://en.wikipedia.org/wiki/Benefit%E2%80%93cost_ratio), student reviews, and curriculum. Not all certifications are equally valuable, so it’s important to choose ones that are well-respected in the industry and align with your career goals.

Now, please keep in mind that the certifications mentioned here are just a few that I personally recommend if you're trying to break into pentesting or Red Teaming. You don’t need to go out and complete every single one. Just use this list as a starting point and do your own research to determine which certifications align with your interests and career goals. This blog post is already long as it is, so I rather not ramble. 

Additionally, there's a very good [Security Certification Roadmap](https://pauljerimy.com/security-certification-roadmap/) that you can utilize to look for other certificates across the different areas of security. It’s a great resource to help you explore additional options that might be a good fit for you if you're looking to break into other parts of security which aren't focused around offensive security.

So, what certifications do I recommend for penetration testing? I’m glad you asked! Here are some of my favorite certifications that can help you break into the pentesting field. I highly recommend the following:

- [HTB Certified Penetration Testing Specialist](https://academy.hackthebox.com/preview/certifications/htb-certified-penetration-testing-specialist)
- [Offensive Security Certified Professional (OSCP)](https://www.offsec.com/courses/pen-200/)
- [Offensive Security Experienced Penetration Tester (OSEP)](https://www.offsec.com/courses/pen-300/)
- [Offensive Security Exploit Developer (OSED)](https://www.offsec.com/courses/exp-301/)
- [Zero-Point Security: Red Team Ops](https://training.zeropointsecurity.co.uk/courses/red-team-ops)
- [Zero-Point Security: Red Team Ops II](https://training.zeropointsecurity.co.uk/courses/red-team-ops-ii)
- [CompTIA Security+](https://certification.comptia.org/certifications/security)

Usually the OSCP will be the industry standard, and open more doors for you, but the HTB CPTS is also really good and it's cheaper (~$500 USD). So if you are paying for certificates out of pocket and can't afford much, then I would recommend you take the CPTS and take the OSCP once you can have someone pay for it.

While SANS certifications are still respected, they are very expensive, so I tend not to recommend them anymore unless you’re ready for a significant investment or can have your employer pay for them.

- [SANS SEC542 - GWAPT](https://www.sans.org/course/web-app-penetration-testing-ethical-hacking)
- [SANS SEC560 - GPEN](https://www.sans.org/course/network-penetration-testing-ethical-hacking)
- [SANS SEC565 - GRTP](https://www.sans.org/cyber-security-courses/red-team-operations-adversary-emulation/)
- [SANS SEC575 - GMOB](https://www.sans.org/course/mobile-device-security-ethical-hacking)
- [SANS SEC660 - GXPN](https://www.sans.org/course/advanced-penetration-testing-exploits-ethical-hacking)

Additionally, here are some other security certificates with a good reputation that are not related to penetration testing:

- [AWS Certified Security Specialist](https://aws.amazon.com/certification/certified-security-specialty/)
- [Microsoft Certified: Azure Security Engineer Associate](https://learn.microsoft.com/en-us/credentials/certifications/azure-security-engineer/?practice-assessment-type=certification)
- [MRE - Certified Reverse Engineer](https://www.mosse-institute.com/certifications/mre-certified-reverse-engineer.html)
- [SANS GCIH - Incident Handler](https://www.giac.org/certifications/certified-incident-handler-gcih/)
- [Security Blue Team - Level 1](https://www.securityblue.team/certifications/blue-team-level-1)
- [Security Blue Team - Level 2](https://www.securityblue.team/certifications/blue-team-level-2)
- [Zero2Automated: Advanced Malware Analysis Course](https://courses.zero2auto.com/adv-malware-analysis-course)

### 3. Training & Practice:

In addition to college, self-learning, and certifications, hands-on training and practice are crucial when breaking into the field of security. While formal training often ties into certifications, I believe training deserves its own focus as a separate and ongoing part of your learning journey.

There are a ton of resources out there that can provide you with continues training resources. Since I’ve already provided numerous resources for developing technical skills earlier, this section will focus on platforms where you can safely and legally practice your hacking techniques.

Just note that before I start listing everything, this isn't an exhaustive list. These resources are just a starting point to help you build foundational skills and expand your knowledge. If for some reason you don't know something, want to learn about a new topic, or can't find a resource, then just Google it! You can't be a hacker if you don't practice your Google-Fu!

Anyways, here is a list of resources that will help you practice!

- [AWSGoat: A Damn Vulnerable AWS Infrastructure](https://github.com/ine-labs/AWSGoat)
- [CTF365](https://ctf365.com/)
- [CTFTime](https://ctftime.org/)
  - [What is CTF Time?](https://www.youtube.com/watch?v=8ev9ZX9J45A)
- [Exploit Exercises](https://exploit-exercises.com/)
- [Game of Hacks (Source Code Review)](http://www.gameofhacks.com/)
- [GOAD (Game Of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD)
- [Google Gruyere](https://google-gruyere.appspot.com/)
- [Google XSS Game](https://xss-game.appspot.com/)
- [Hack The Box](https://www.hackthebox.eu/)
- [Hack This Site](https://www.hackthissite.org/)
- [Hacker101 CTF](https://ctf.hacker101.com/)
- [Hacking Lab](https://www.hacking-lab.com/index.html)
- [HackThis!!](https://www.hackthis.co.uk/)
- [Metasploitable 2](https://metasploit.help.rapid7.com/docs/metasploitable-2)
- [OverTheWire](http://overthewire.org/wargames/)
- [OWASP Vulnerable Web Applications Directory Project](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=Main)
- [Pentestit Labs](https://lab.pentestit.ru/)
- [PWNABLE](http://pwnable.kr/)
- [Ringzer Zero Team](https://ringzer0team.com/challenges)
- [RingZer0 Team Online CTF](https://ringzer0ctf.com/)
- [Root-Me](https://www.root-me.org/?lang=en)
- [TryHackMe](https://tryhackme.com/)
- [Vulnhub](https://www.vulnhub.com/)
## Caveats and a Word of Caution:

Alright, before we continue any further, let's address the elephant in the room - the overwhelming number of "experts" trying to sell you cybersecurity courses or promising you a six-figure salary in under a year.

When doing research on your own, be cautious of so called cybersecurity "experts" who have little to no actual industry experience but are eager to sell you courses or merchandise. In addition, be wary of certain "content creators" who may mislead you with their advice or teachings. There is an abundance of paid courses created by these individuals who, despite their claims, are not qualified to teach, nor should they be regarded as true "experts" in the field. These sort of practices are especially harmful toward beginners because they struggle to distinguish between legitimate educational resources and misleading content.

It’s easy to get swept up in the vast amount of content available online, but as a beginner, it's crucial for you to validate the credibility of those offering you advice, especially if they are trying to sell you something as well. 

It's important to also note that there are many fantastic, and highly skilled individuals in the cybersecurity industry who offer valuable courses and share their expertise. These experts are definitely worth learning from. However, teaching is a skill in itself, and unfortunately not all experts are effective educators. While some courses may offer great insights, they might not be the best fit for beginners or may not be taught in the most effective way. In some cases, complex topics are only briefly covered, leaving participants to either teach themselves or worse, leave them feeling more confused than they were before. So be cautious of courses that claim "no experience required" when in reality a solid foundation of knowledge is essential to truly grasp the material.

I recommend that everyone take the time to verify the background of the educator, content creator, or expert before trusting their guidance or taking part in their course. Check for real-world experience, relevant credentials, and a proven track record to ensure you're learning from someone truly qualified. Also, look up student reviews, and curriculum for a course before you pull the trigger.

A simple Google or Reddit search about the person or course will bring up a ton of information, and unfortunately at times some slander. While not everything you come across may be accurate, there can sometimes be a grain of truth in those negative claims. Regardless, it's important to approach all information you see online with caution and take it with a grain of salt.

Now this is US specific, but when it comes to the promise of a six-figure salary in cybersecurity it's important to manage expectations. While it’s technically possible to earn that kind of salary after 2-4 years, it’s highly improbable without prior experience or a strong technical skill set. Most professionals in the field spend several years building their expertise before reaching that level of compensation. So while it's not completely out of the question, success in cybersecurity generally takes time, experience, and dedication - so don't get too caught up in the craze of making a fortune early on in your career or falling for a scam educational program that guarantees you that salary after six months to a year. Don't believe me? See the "[r/cybersecurity: 2024 End of Year Salary Sharing Thread](https://www.reddit.com/r/cybersecurity/comments/1ia1iuu/2024_end_of_year_salary_sharing_thread/)".

Additionally, I have to say, but if you’re trying to break into cybersecurity for the money, you're setting yourself up for failure. This industry moves so fast that without a genuine passion for the work, you’ll quickly burn out. This field demands constant learning and problem solving, and if you’re not truly invested then you'll struggle to keep up and soon enough the grind will drain you. If you're not genuinely interested in the field, it’s probably better to step away now for your own good, rather than chasing a paycheck that’ll leave you miserable in the long run.

After saying all of this, you might be wondering, "**Why should I trust you**?" Honestly, you shouldn’t. I'm just another person on the internet. But if you're curious about my credentials, at the time of writing this, I have around 9 years of experience in the security industry, with 7 of those years spent in consulting. Everything I’ve shared in this post comes from my own personal experiences and the lessons I’ve learned throughout my career. My goal in writing this post is to help you navigate the cybersecurity field more effectively and avoid pitfalls, but ultimately, I'm also trying to teach you to do your own research and make informed decisions on your own.
## Burnout:

Burnout and mental health in this field are a critical topic that also needs to be addressed before we move forward. It’s so easy to get lost in the hustle and forget that maintaining a balance in your life is just as important as learning new technical skills.

Burnout in this industry is so damn common that it’s almost inevitable. The work in this field is demanding, with long hours, constant learning, and trying to stay up to date in an industry that never sleeps. At some point, you’ll hit a wall. You’ll feel exhausted, frustrated, and feel like you’re never quite catching up. That feeling? It sucks. At this point you'll start to lose interest, and question if this career is really for you, or if you're actually smart enough. But trust me, **everyone goes through this**. It’s not a matter of "if", it’s a matter of "when".

The key to not burning out is knowing when to step back when you spot the signs of burnout. When you feel like you hit a wall, give yourself the time to recharge, get your priorities straight, and don’t try to power through when you’re running on fumes. No amount of studying, coding, or hacking will do you any good if your mind and body are drained. Burnout is a real threat to your mental and physical health so you have to **take care of yourself** first and foremost.

This means that you need to have other hobbies and activities that you can do to unwind, other than sitting at your computer. Literally, go touch grass! Go outside for a walk, spend some time in the sun, go swimming, pickup a sport or martial arts, or go hit the gym. In addition to other hobbies, know your limits and set boundaries.

On top of all that, **don't compare yourself to others**! This is a surefire way to wreck your mental health. Everyone’s journey in cybersecurity is different and some people pick things up faster than others. While it might seem like a lot of people are more experienced than you, that doesn’t mean you’re falling behind. It’s **your journey**, so don’t get distracted by other people’s timelines or achievements. 

Sure, you can look up to those people in the industry and get inspired by their achievements, but don’t set unrealistic expectations for yourself based on what others have accomplished. Some of these people have been hacking or learning since they were like 12, or have been in the industry for 10+ years. The biggest problem in the industry is always seeing other's awesome research or the "end result", but what you don't see is the hundreds of hours that person spent, or the amount of times they failed in order to achieve that goal or finish that research.

Impostor syndrome is real, and it can kick in hard when you feel like you’re not measuring up. But the truth is, you **are** making progress, even if it doesn’t always feel that way. Remember, this isn’t a sprint; it’s a marathon. Do things step by step at your own pace, take constant breaks, focus on one thing at a time, and don’t try to tackle everything at once. Balance is key.

Alright, with that out of the way, let's get back into the post.
## The Experience:

With a college degree and a few certificates under your belt, you're on the right path, but is that enough to land you a dream job in security? How can you gain the hands-on experience needed to stand out?

While relevant coursework and certifications can potentially help you secure an entry-level security role, they typically won’t be sufficient for more advanced positions like a security consultant or penetration tester, unless you already have significant practical experience. That being said, if you're exceptionally skilled, can demonstrate your abilities with a strong portfolio, and perform well in interviews, it's possible to break into that position early.

In my experience, many of the professionals I work with have at least 5-10 years of experience in other technical roles, such as development, system administration, network engineering, security operations ([SOC](https://digitalguardian.com/blog/what-security-operations-center-soc)), incident response, and even malware analysis and reverse engineering. 

So, does that mean you need many years of experience to become a penetration tester? Not at all! In today's day and age you can definitely achieve this goal within a year or two if you are passionate. However, you do need a solid understanding of key concepts and practical skills. When I started my role as an Associate Security Consultant I had about three years of direct security experience, plus roughly five years of what I’d call "learning experience."

This learning experience can include a variety of activities, such as participating in Capture The Flag (CTF) challenges, reading books and articles, gaining familiarity with network infrastructure and enterprise technologies, and practicing in virtual labs. While all of this practice is valuable, the real question is: can you effectively apply that knowledge in real-world situations? 

This is where working experience comes into play. Just because you know something theoretically doesn’t mean you’ll always know how to apply it in practice, or why something might not work as expected. For example, let's say you're doing a network pentest and have a shell on a Windows machine. You successfully capture some [NetNTLM](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4) hashes and attempt a [Pass the Hash](https://attack.mitre.org/wiki/Technique/T1075) attack on another device, but it fails. Why?

If your answer is "I don't know", or "I don't have privileges" - then good luck explaining that to a client. What actually happened is that you were working with a NetNTLM hash, which is used for network authentication and is derived from a challenge-response mechanism based on the user’s NT hash. You **cannot** perform a pass-the-hash attack using NetNTLM hashes due to the [MS08-068](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-068) patch. Additionally, if you had valid NTLM hashes but tried to relay them, then it’s possible that [SMB Signing](https://blogs.technet.microsoft.com/josebda/2010/12/01/the-basics-of-smb-signing-covering-both-smb1-and-smb2/) was enabled, which would prevent you from executing commands within the context of the user.

With enough practical experience, you would likely have identified this issue earlier. But since you carelessly executed the attack without doing proper reconnaissance or understanding the nuances of how Active Directory environments or corporate networks are configured, you could have easily triggered an alert in the network.

At this point you might be asking yourself... "_How can I learn all of this? Where do I start?_" and to honestly answer that questions, all I can say is - get a job!

To truly become a well-rounded penetration tester, you need to gain hands-on experience and deepen your understanding of the specific areas you want to specialize in. You can’t learn everything from books or labs alone, real-world experience is key.

Want to become a web or network penetration tester? Then consider starting out as a junior system administrator, network engineer, SOC analyst, or security analyst for a company. These roles will give you hands-on experience with how networks are set up, protected, and how these defenses can be bypassed. Working these jobs will also teach you a lot about enterprise tools, configurations, and technologies like Active Directory, which are crucial in understanding network security from a practical standpoint.

Want to be a hardware hacker? Start by working as a junior developer who focuses on software engineering or hardware system design and development. These roles will help you build the technical foundation needed for hardware-related penetration testing.

If you're still in school, get an internship! I honestly believe that students who don't get an internship during college are wasting their time and money and are missing out on valuable opportunities. Internships provide real-world experience that academic programs often can’t match. After you graduate, you might even have enough experience and knowledge to become a junior pentester, but you will need to work hard to do so!

While you’re actively working, don’t stop learning! If there’s something new you don’t fully understand or you want to learn about, then start by Googling it first, read a blog post or two, and then go ask a senior member about it. Want to do something else on the team, like pentest a website, or develop a new tool? Ask! The answer is always no if you don't ask!

At the same time, you can also gain valuable experience outside of work by dedicating your personal time to learning and experimenting. This could mean developing your own tools or scripts, setting up a lab environment at home, writing blog posts, contributing to open-source projects on GitHub, joining a CTF team, or even creating vulnerable machines for platforms like VulnHub or Hack The Box.

While you're doing all of that, become active and engage in the broader InfoSec and hacker community. Attend local security meetups or hacker spaces, go to security conferences, and create a Twitter/Mastadon account to follow and interact with well-known figures in the field. Participate in security-focused Reddit communities, join relevant Slack/Discord channels, and immerse yourself in the network of like-minded individuals who can help expand your knowledge and opportunities.

Doing this will allow you to become better known in the community and will allow you to show your work, skill, and passion toward the field. Who knows, maybe someone might offer you your dream job!

## The Job Search:

Now that you've gained some experience, earned a few certifications, and stayed active in the community while continuously learning, it's now time to look for your dream job!

Searching for a job as a pentester, or any security job for that matter, can feel overwhelming at first, especially since some companies require more experience than others. Additionally if a college degree or prior experience is a prerequisite, securing a job might seem challenging if you don't hold that relevant degree. But don’t let that discourage you!

There are two main paths that you can take to work as a pentester. The "Internal" path and the "External" path.

### The Internal Path:

The Internal path while generally easier, tends to take a bit longer than the external path. On this path you aim to work as part of an internal security team, where you’ll focus on activities like red teaming, penetration testing, and conducting security audits specifically for the company. To pursue this route it’s ideal to start by looking for internships or junior positions at companies with established security teams or those in the process of building one.

Usually the company will expect you to have a college degree, a couple of certifications, and some prior experience as a system administrator or security analyst. Internal security teams rely on you to have a deep understanding of how their network is configured, the security protections in place, and where vulnerabilities or points of failure could exist.

Starting early as a junior member of the team or even working in IT for that company will allow you to gain the knowledge you need to understand their systems, making it easier to demonstrate your capabilities when trying to apply. Additionally, getting promoted or transitioning to a different role within the company is usually much smoother than applying externally, since the team is already familiar with your skills and work ethic.

### The External Path:

The external path is usually the quicker of the two routes, as you can be hired relatively quickly if you have the right skills and know how to demonstrate them. On this path you aim to work as a security consultant usually with a large organization or consulting firm. From there, you'll be hired by other companies to perform penetration tests on their web applications, networks, hardware, and more. To pursue this route, it’s best to look for associate or junior security consulting/pentesting positions at established consulting firms.

Usually self-respecting consulting firms that offer high-quality work won't care if you have a degree or not, but they will look to see if you have certifications, previous working experience, and if you can properly demonstrate your skills. Such companies will usually put you through a rigorous hiring process that includes phone interviews, technical challenges, and in-person interviews. You’ll likely be tested on a wide range of topics, from web application security and network penetration testing to reverse engineering protocols and binary applications.

Once hired, these companies will invest in your professional development. They’ll provide resources, a training budget, test labs, and opportunities to shadow senior team members. However, be prepared to learn quickly! After the company invests in your training they expect you to be able to contribute to billable projects within one to three months, so the learning curve can be steep.
## My Path to Becoming a Pentester:

When I first started working as a Security Consultant back in 2018, I would tell people what I did for a living. But as soon as they learned how old I was and the number of years of experience I had, they’d laugh and usually respond with... "_Well that’s impossible!_"

Honestly, nothing is impossible if you really put in the effort! What many people didn't see was the countless hours I spent teaching myself new things, the super late nights I spent reading blogs, hacking boxes on Hack The Box, and putting in the work to become the best I can be - and even then I was still just scratching the surface.

My journey to becoming a pentester started when I was still in high school. I knew I wanted to be a "l33t hackzor" but I didn't really know where to start. The summer before my graduation I spent a lot of time Googling and reading Reddit threads about how to become a security expert. A common piece of advice that was given was to start in IT, such as helpdesk, and then move into system administration, and eventually transition into security.

So that was my plan - go to college, get a job in IT, and work my way up. I started college in 2014, pursuing a Bachelor’s in Information Technology with a concentration in Information Security and a minor in Mathematics. On my second year of college in 2015 I landed an IT internship doing client service work, also known as help desk support. During my time there I gained a lot of hands on experience with Active Directory, networks, learned how a company functions, and how things are configured. I even learned SQL, PowerShell, and Python as well.

While working in client services, I met and became friends with one of the Senior Security Analysts, who later went on to become my mentor. I constantly asked him questions about security, and he always pointed me to new resources. That’s when my curiosity for hacking truly sparked. After learning a few things I always tried applying what I knew to client services, and suggested more security minded procedures.

I spent countless late nights after school and work reading about security, hacking, malware, and literally anything I could get my hands on. That’s when I discovered Kali Linux and VulnHub and began learning how to exploit vulnerabilities and "pop boxes."

About a year and a half into my internship I learned that my mentor was leaving for another job, and little did I know, I would be taking his place. A few weeks before his departure the Director of Security approached me and asked if I would like to spend a few hours a week working in security to help out with the workload - you know I said yes!

What started as a few hours a week turned into a full-time security internship for me as the director recognized my passion for security (thanks for taking a chance on me [Sam](https://x.com/sammonasteri?mx=2!)). Once hired on as a Security Intern, I took the time to get my first certificate, the CompTIA Security+. This certificate was honestly the best learning experience for me as it provided me the foundational knowledge I needed to succeed at my job. 

After obtaining my certification I kept pushing myself further. I bought a lot of books, and began reading them - from Web Hackers Handbook to Hacking, The Art of Exploitation. When I wasn’t reading, I practiced on platforms like VulnHub, Hack The Box, and Pentestit Labs. I also started writing blogs, watching security videos, learning languages like Python, C, PHP, Ruby, and Assembly, and also started attending security conferences!

It was during my security internship where my boss suggested I conduct my first web application penetration test. I was ecstatic - I was finally going to be doing what I wanted. From there I went on to become the lead DFIR and Pentester for my security team and mainly focused on deploying a secure environment, doing incident response, and risk assessments for new applications on our network. 

I graduated about a year later, and was hired full time as a Security Analyst. While working there, I earned my OSCP certification, all while continuing to spend my nights learning new things, reading all the books and blogs I could, and doing CTFs.

However, after about a year, I started to burn out. I was in security, I put a lot of effort into it, but I wasn't doing what I wanted to... and that was pentesting.

I decided to make a change and applied to NCC Group as an Associate Security Consultant. The application process was long and rigorous, lasting about 3-4 months, with multiple interviews and challenges. After what felt like an eternity, I finally received the acceptance letter and took the job.

I spent about three years working at NCC Group, and I was fortunate to gain extensive experience conducting security assessments for clients across a wide range of industries. My main focus was on web application and network pentesting, and over time after proving myself, I joined the Red Team - which further allowed me to expand my expertise into offensive security development and physical penetration testing. I also had the opportunity to work on some awesome hardware assessments, including hacking ATMs, self-driving vehicles, trains, and even shipping ports.

Even while traveling and working on various projects, one thing remained constant: I continued to spend countless late nights learning and teaching myself new things. If I wasn’t reading blogs about the latest offensive techniques, I was diving into RFCs or reviewing documentation related to the systems I was trying to hack or exploit, all to refine my skills and be a better consultant the next day.

During my time at NCC Group, I took several courses to expand my skills, one of which was _Dark Side Ops_ from Silent Break. This course was designed for offensive security enthusiasts interested in development, and it was a fantastic course which taught me how to build and modify custom offensive tools to bypass the latest security countermeasures. It also significantly enhanced my ability to think critically, operate effectively, and develop TTPs similar to those used by sophisticated real-world attackers. This knowledge laid the foundation for me to create my own tools and dive deeper into security research. Additionally, I earned my Offensive Security Certified Expert (OSCE - now retired) certification, which further strengthened my research and exploitation capabilities.

After gaining all that experience, I decided to release a blog post on utilizing syscalls in C# which was a hot topic at the time. Fortunately for me that blog gained a lot of traction, and the red team at CrowdStrike took notice. They reached out to me with a job offer to join the red team and offensive development team. Since then, I have been working as a Principle Security Consultant at CrowdStrike, doing some awesome work with an amazing team. Despite all of that, I still dedicate my nights to learning new things and continuously improving myself.
## Closing:

Finally we've reached the end of this blog post! I know there’s a ton of information here, so try not to get overwhelmed.

Honestly, I could continue writing more about how to become a pentester as this is only the tip of the iceberg. But I'm not going do that. The reason for that is simple: I want you to take these resources, go out there, and learn on your own. Learn to be independent, seek out resources yourself, and connect the dots as you go.

What I mean by that is, once you understand the basics, the rest will come easy as you'll know what knowledge gaps you need to fill. I know many of you want to become a pentester or work in security like right now, but remember, it takes time. Rome wasn’t built in a day, so take the time to learn everything you can. Enjoy the process, and you’ll get to your end goal faster than you think! Remember, the journey to becoming a security professional is never linear, but with dedication, curiosity, and a willingness to keep learning, you can make great strides.

In the end, the answers to your question on "_How can I become a pentester?_" is: Master the fundamentals of networking, web applications, and security. Practice relentlessly. Get certified and start working in a junior role to further build out your foundational and technical skills. Engage with the community on platforms like Twitter (X), Reddit, Discord and at security conferences. Build tools, write blog posts about your security adventures, and contribute to open-source projects. But most importantly, **never stop learning** and **never doubt yourself**!

I truly hope that this post helps you in some way, shape, or form, and I wish you the best on your road to a fulfilling security career.

Cheers!
## Kudos

I would like to sincerely thank [V3ded](https://twitter.com/v3ded) and [noodlearms](https://x.com/infosecnoodle) for proofreading this blog post, providing critical feedback and adding in a few important details before it's release. You guys are awesome for taking the time to review this monster of a post for accuracy, readability and for providing your expertise. Thank you!
