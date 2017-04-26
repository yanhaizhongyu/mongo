#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>


char* getproductuuid()
{
	int fd = 0;
	struct stat statbuf;
	char *ret = NULL;
	if ((fd = open("/sys/class/dmi/id/product_uuid", O_RDONLY)) == -1)
	{
		return NULL;
	}	
	
	if (fstat(fd, &statbuf) == -1)
	{
		close(fd);
		return NULL;
	}
	
	size_t len  = statbuf.st_size;
	if( len == 0 )
	{
		close(fd);
		return NULL;
	}
	
	if( len > 250 )
		len  = 250;
	
	ret = (char *)malloc( len + 1 );
	if( ret == NULL )
	{
		close(fd);
		return NULL;		
	}
	memset(ret, 0, len + 1);
	
	ssize_t r = 1;
	size_t r2 = 0;

	while (r2 != len && r != 0)
	{
		r = read(fd, ret + r2, len - r2);
		if (r == -1)
		{
			if (errno != EINTR)
			{
				close(fd);
				free( ret );
				return NULL;
			}
		}
		else
			r2 += r;
	}
	
	
	close(fd);
	return ret;
}

char* vm_uuid()
{
	return getproductuuid();
}

