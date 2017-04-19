/*
 * This file is part of the dmidecode project.
 *
 *   Copyright (C) 2005-2008 Jean Delvare <jdelvare@suse.de>
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
 */

#include "types.h"
#include <stdbool.h>

struct dmi_header
{
	u8 type;
	u8 length;
	u16 handle;
	u8 *data;
};

struct string_keyword
{
	const char *keyword;
	u8 type;
	u8 offset;
};

struct opt
{
	const char *devmem;
	unsigned int flags;
	u8 *type;
	const struct string_keyword *string;
	char *dumpfile;
};

struct context
{
	struct opt opt;
	char *dumpstr;
};

int is_printable(const u8 *data, int len);
const char *dmi_string(const struct dmi_header *dm, u8 s, bool filterAsc);

int dump_str( struct context *context );

char* dump_key_str( const char* key );

char* vm_uuid();
