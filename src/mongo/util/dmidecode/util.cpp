/*
 * Common "util" functions
 * This file is part of the dmidecode project.
 *
 *   Copyright (C) 2002-2015 Jean Delvare <jdelvare@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#ifdef USE_MMAP
#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif /* !MAP_FAILED */
#endif /* USE MMAP */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>

#include "types.h"
#include "util.h"

char* errnostr(const char *prefix)
{
	size_t errmsglen = 0;
			
	if( prefix != NULL && *prefix)
		errmsglen += strlen(prefix) + 1;
	
	char errstr[512]={'\0'};
	strerror_r(errno, errstr, 512);
	errmsglen += strlen(errstr);
	errmsglen += 1;
	
	char *errmsg = (char *)malloc(errmsglen); 
	memset(errmsg, 0, errmsglen);
	
	if( prefix != NULL && *prefix )
	{
		strcat( errmsg, prefix );
		strcat( errmsg, ":" );
	}
	
	strcat(errmsg, errstr);
	return errmsg;

}

char* errnostr1(const char *prefix0, const char *prefix)
{
	size_t errmsglen = 0;
	if( prefix0 != NULL && *prefix0)
		errmsglen = strlen(prefix0) + 1;		
			
	if( prefix != NULL && *prefix)
		errmsglen += strlen(prefix) + 1;

	
	char errstr[512]={'\0'};
	strerror_r(errno, errstr, 512);
	errmsglen += strlen(errstr);
	errmsglen += 1;
		
	char *errmsg = (char *)malloc(errmsglen); 
	memset(errmsg, 0, errmsglen);
	
	if( prefix0 != NULL && *prefix0)
	{
		strcat( errmsg, prefix0 );
		strcat( errmsg, " " );
	}
	
	if( prefix != NULL && *prefix )
	{
		strcat( errmsg, prefix );
		strcat( errmsg, ":" );
	}
	
	strcat(errmsg, errstr);
	return errmsg;
}

char* msprintf(const char *strformat, ...)
{
  va_list args;
  va_start (args, strformat);
  size_t len = vsnprintf (NULL,0,strformat, args);
  va_end (args);
  
  char *ret = (char *)malloc(len + 1);
  memset(ret, 0, len + 1);
    
  va_start (args, strformat);
  vsprintf(ret, strformat, args);
  va_end (args);
  
  return ret;
}

char* amsprintf(char* str, const char *strformat, ...)
{
  va_list args;
  va_start (args, strformat);
  size_t len = vsnprintf (NULL,0,strformat, args);
  va_end (args);
  
  size_t len0 = 0;
  if( str != NULL )
  	len0 = strlen(str);
  len += len0;
  char *ret = (char*)realloc(str, len + 1);
  
  va_start (args, strformat);
  vsnprintf(ret + len0,len + 1 - len0, strformat, args);
  va_end (args);
  return ret;	
}

static int myread(int fd, u8 *buf, size_t count, const char *prefix, char** error)
{
	ssize_t r = 1;
	size_t r2 = 0;

	while (r2 != count && r != 0)
	{
		r = read(fd, buf + r2, count - r2);
		if (r == -1)
		{
			if (errno != EINTR)
			{
				close(fd);
				if( error != NULL )
					*error = errnostr(prefix);
				return -1;
			}
		}
		else
			r2 += r;
	}

	if (r2 != count)
	{
		close(fd);
		if( error != NULL )
			*error = msprintf("%s: Unexpected end of file\n", prefix);
		return -1;
	}

	return 0;
}

int checksum(const u8 *buf, size_t len)
{
	u8 sum = 0;
	size_t a;

	for (a = 0; a < len; a++)
		sum += buf[a];
	return (sum == 0);
}

/*
 * Reads all of file, up to max_len bytes.
 * A buffer of max_len bytes is allocated by this function, and
 * needs to be freed by the caller.
 * This provides a similar usage model to mem_chunk()
 *
 * Returns pointer to buffer of max_len bytes, or NULL on error, and
 * sets max_len to the length actually read.
 *
 */
void *read_file(size_t *max_len, const char *filename, char** error)
{
	int fd;
	size_t r2 = 0;
	ssize_t r;
	u8 *p;

	/*
	 * Don't print error message on missing file, as we will try to read
	 * files that may or may not be present.
	 */
	if ((fd = open(filename, O_RDONLY)) == -1)
	{
		if (errno != ENOENT)
			if( error != NULL )
				*error = errnostr(filename);
		return(NULL);
	}

	if ((p = (u8*)malloc(*max_len)) == NULL)
	{
		if( error != NULL )
			*error = errnostr("malloc");
		return NULL;
	}

	do
	{
		r = read(fd, p + r2, *max_len - r2);
		if (r == -1)
		{
			if (errno != EINTR)
			{
				close(fd);
				if( error != NULL )
					*error = errnostr(filename);
			
				free(p);
				return NULL;
			}
		}
		else
			r2 += r;
	}
	while (r != 0);

	close(fd);
	*max_len = r2;

	return p;
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
void *mem_chunk(off_t base, size_t len, const char *devmem, char** error)
{
	void *p;
	int fd;
#ifdef USE_MMAP
	struct stat statbuf;
	off_t mmoffset;
	void *mmp;
#endif

	if ((fd = open(devmem, O_RDONLY)) == -1)
	{
		if( error != NULL )
			*error = errnostr(devmem);
	
		return NULL;
	}

	if ((p = malloc(len)) == NULL)
	{
		if( error != NULL )
			*error = errnostr("malloc");
		goto out;
	}

#ifdef USE_MMAP
	if (fstat(fd, &statbuf) == -1)
	{
		if( error != NULL )
			*error = errnostr1(devmem, "stat");		
		goto err_free;
	}

	/*
	 * mmap() will fail with SIGBUS if trying to map beyond the end of
	 * the file.
	 */
	if (S_ISREG(statbuf.st_mode) && base + (off_t)len > statbuf.st_size)
	{
		if( error != NULL )
			*error = msprintf("mmap: Can't map beyond end of file %s\n",devmem);		

		goto err_free;
	}

#ifdef _SC_PAGESIZE
	mmoffset = base % sysconf(_SC_PAGESIZE);
#else
	mmoffset = base % getpagesize();
#endif /* _SC_PAGESIZE */
	/*
	 * Please note that we don't use mmap() for performance reasons here,
	 * but to workaround problems many people encountered when trying
	 * to read from /dev/mem using regular read() calls.
	 */
	mmp = mmap(NULL, mmoffset + len, PROT_READ, MAP_SHARED, fd, base - mmoffset);
	if (mmp == MAP_FAILED)
		goto try_read;

	memcpy(p, (u8 *)mmp + mmoffset, len);

	if (munmap(mmp, mmoffset + len) == -1)
	{
		if( error != NULL )
			*error = errnostr1(devmem, "munmap");			
	}

	goto out;

try_read:
#endif /* USE_MMAP */
	if (lseek(fd, base, SEEK_SET) == -1)
	{
		if( error != NULL )
			*error = errnostr1(devmem, "lseek");			
		goto err_free;
	}

	if (myread(fd, (u8*)p, len, devmem, error) == 0)
		goto out;

err_free:
	free(p);
	p = NULL;

out:
	if (close(fd) == -1)
		if( error != NULL )
			*error = errnostr(devmem);	

	return p;
}

int write_dump(size_t base, size_t len, const void *data, const char *dumpfile, int add, char** error)
{
	FILE *f;

	f = fopen(dumpfile, add ? "r+b" : "wb");
	if (!f)
	{
		if( error != NULL )
			*error = errnostr1(dumpfile, "fopen");
		return -1;
	}

	if (fseek(f, base, SEEK_SET) != 0)
	{
		if( error != NULL )
			*error = errnostr1(dumpfile, "fseek");
		goto err_close;
	}

	if (fwrite(data, len, 1, f) != 1)
	{
		if( error != NULL )
			*error = errnostr1(dumpfile, "fwrite");
		goto err_close;
	}

	if (fclose(f))
	{
		if( error != NULL )
			*error = errnostr1(dumpfile, "fclose");
		return -1;
	}

	return 0;

err_close:
	fclose(f);
	return -1;
}

/* Returns end - start + 1, assuming start < end */
u64 u64_range(u64 start, u64 end)
{
	u64 res;

	res.h = end.h - start.h;
	res.l = end.l - start.l;

	if (end.l < start.l)
		res.h--;
	if (++res.l == 0)
		res.h++;

	return res;
}
