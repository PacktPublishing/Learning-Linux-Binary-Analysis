## $5 Tech Unlocked 2021!
[Buy and download this Book for only $5 on PacktPub.com](https://www.packtpub.com/product/learning-linux-binary-analysis/9781782167105)
-----
*If you have read this book, please leave a review on [Amazon.com](https://www.amazon.com/gp/product/1782167102).     Potential readers can then use your unbiased opinion to help them make purchase decisions. Thank you. The $5 campaign         runs from __December 15th 2020__ to __January 13th 2021.__*

# Learning Linux Binary Analysis

<a href="https://www.packtpub.com/networking-and-servers/learning-linux-binary-analysis?utm_source=github&utm_medium=repository&utm_campaign=9781782167105 "><img src="https://dz13w8afd47il.cloudfront.net/sites/default/files/imagecache/ppv4_main_book_cover/7105OS.jpg" alt="Learning Linux Binary Analysis" height="256px" align="right"></a>

This is the code repository for [Learning Linux Binary Analysis](https://www.packtpub.com/networking-and-servers/learning-linux-binary-analysis?utm_source=github&utm_medium=repository&utm_campaign=9781782167105 ), published by Packt.

**Learning Linux Binary Analysis**

## What is this book about?
Learning Linux Binary Analysis is packed with knowledge and code that will teach you the inner workings of the ELF format, and the methods used by hackers and security analysts for virus analysis, binary patching, software protection and more.

This book covers the following exciting features:
Explore the internal workings of the ELF binary format 
Discover techniques for UNIX Virus infection and analysis 
Work with binary hardening and software anti-tamper methods 
Patch executables and process memory 
Bypass anti-debugging measures used in malware 
Perform advanced forensic analysis of binaries 
Design ELF-related tools in the C language 
Learn to operate on memory with ptrace 

If you feel this book is for you, get your [copy](https://www.amazon.com/dp/1782167102) today!

<a href="https://www.packtpub.com/?utm_source=github&utm_medium=banner&utm_campaign=GitHubBanner"><img src="https://raw.githubusercontent.com/PacktPublishing/GitHub/master/GitHub.png" 
alt="https://www.packtpub.com/" border="5" /></a>

## Instructions and Navigations
All of the code is organized into folders. For example, Chapter02.

The code will look like the following:
```
uint64_t injection_code(void * vaddr)
{
volatile void *mem;
mem = evil_mmap(vaddr, 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
__asm__ __volatile__("int3");
}
```

**Following is what you need for this book:**
If you are a software engineer or reverse engineer and want to learn more about Linux binary analysis, this book will provide you with all you need to implement solutions for binary analysis in areas of security, forensics, and antivirus. This book is great for both security enthusiasts and system level engineers. Some experience with the C programming language and the Linux command line is assumed.

A user will be able to experiment with much of the knowledge in this book (Chapter 1-9) with a variety of operating systems and hardware, although it is specifically focused for Linux 3.2 and higher running on X86 32bit or 64bit architectures.

## Get to Know the Author
Ryan "elfmaster" O'Neill is a computer security researcher and software 
engineer with a background in reverse engineering, software exploitation, security defense, and forensics technologies. He grew up in the computer hacker subculture, the world of EFnet, BBS systems, and remote buffer overflows on systems with an executable stack. He was introduced to system security, exploitation, and virus writing at a young age. His great passion for computer hacking has evolved into a love for software development and professional security research. Ryan has spoken at various computer security conferences, including DEFCON and RuxCon, and also conducts a 2-day ELF binary hacking workshop.
He has an extremely fulfilling career and has worked at great companies such as Pikewerks, Leviathan Security Group, and more recently Backtrace as a software engineer.
Ryan has not published any other books, but he is well known for some of his 
papers published in online journals such as Phrack and VXHeaven. Many of his 
other publications can be found on his website at http://www.bitlackeys.org.

### Suggestions and Feedback
[Click here](https://docs.google.com/forms/d/e/1FAIpQLSdy7dATC6QmEL81FIUuymZ0Wy9vH1jHkvpY57OiMeKGqib_Ow/viewform) if you have any feedback or suggestions.


