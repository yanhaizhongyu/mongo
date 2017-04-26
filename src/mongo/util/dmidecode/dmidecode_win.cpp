#include "dmidecode.h"
#include <windows.h>
#include <stdio.h> 
#include "types.h"

struct dmi_header
{
	u8 type;
	u8 length;
	u16 handle;
	u8 *data;
};

/*
 * Struct needed to get the SMBIOS table using GetSystemFirmwareTable API.
 */
typedef struct _RawSMBIOSData{
    u8	Used20CallingMethod;
    u8	SMBIOSMajorVersion;
    u8	SMBIOSMinorVersion;
    u8	DmiRevision;
    u32	Length;
    u8	SMBIOSTableData[];
} RawSMBIOSData, *PRawSMBIOSData;

static PRawSMBIOSData get_raw_smbios_table(void){
    void *buf = NULL;
    u32 size = 0;
    size = GetSystemFirmwareTable('RSMB', 0, buf, size);
    buf = (void *)malloc(size);
    GetSystemFirmwareTable('RSMB', 0, buf, size);        
	return (PRawSMBIOSData)buf;
}            

/*
* Counts the number of SMBIOS structures present in
* the SMBIOS table.
*
* buff - Pointer that receives the SMBIOS Table address.
*        This will be the address of the BYTE array from
*        the RawSMBIOSData struct.
*
* len - The length of the SMBIOS Table pointed by buff.
*
* return - The number of SMBIOS strutctures.
*
* Remarks:
* The SMBIOS Table Entry Point has this information,
* however the GetSystemFirmwareTable API doesn't
* return all fields from the Entry Point, and
* DMIDECODE uses this value as a parameter for
* dmi_table function. This is the reason why
* this function was make.
*
* Hugo Weber address@hidden
*/
static int count_smbios_structures(const u8 *buff, u32 len){

	int icount = 0;//counts the strutures
	u8 *offset = (u8 *)buff;//points to the actual address in the buff that's been checked
	struct dmi_header *header = NULL;//header of the struct been read to get the length to increase the offset

	//searches structures on the whole SMBIOS Table
	while (offset  < (buff + len)){
		//get the header to read te length and to increase the offset
		header = (struct dmi_header *)offset;
		offset += header->length;

		icount++;

		/*
		* increses the offset to point to the next header that's
		* after the strings at the end of the structure.
		*/
		while ((*(WORD *)offset != 0) && (offset < (buff + len))){
			offset++;
		}

		/*
		* Points to the next stucture thas after two null BYTEs
		* at the end of the strings.
		*/
		offset += 2;
	}

	return icount;
}


static void to_dmi_header(struct dmi_header *h, u8 *data)
{
	h->type = data[0];
	h->length = data[1];
	h->handle = WORD(data + 2);
	h->data = data;
}

static char* dmi_system_uuid(const u8 *p, u16 ver)
{
	int only0xFF = 1, only0x00 = 1;
	int i;

	for (i = 0; i < 16 && (only0x00 || only0xFF); i++)
	{
		if (p[i] != 0x00) only0x00 = 0;
		if (p[i] != 0xFF) only0xFF = 0;
	}

	if (only0xFF)
	{
		return NULL;
	}
	if (only0x00)
	{
		return NULL;
	}

	/*
	* As off version 2.6 of the SMBIOS specification, the first 3
	* fields of the UUID are supposed to be encoded on little-endian.
	* The specification says that this is the defacto standard,
	* however I've seen systems following RFC 4122 instead and use
	* network byte order, so I am reluctant to apply the byte-swapping
	* for older versions.
	*/

	char chUUID[256];
	if (ver >= 0x0206)
		sprintf(chUUID, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
	else
		sprintf(chUUID, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

	return strdup(chUUID);
}

static char* dmi_table_frombuf(u16 len, u16 num, u16 ver, u8 *buf)
{
	u8 *data = buf;
	int i = 0;

	while (i < num && data + 4 <= buf + len) /* 4 is the length of an SMBIOS structure header */
	{
		u8 *next;
		struct dmi_header h;
		int display;

		to_dmi_header(&h, data);

		/*
		* If a short entry is found (less than 4 bytes), not only it
		* is invalid, but we cannot reliably locate the next entry.
		* Better stop at this point, and let the user know his/her
		* table is broken.
		*/
		if (h.length < 4)
		{
			break;
		}

		/* In quiet mode, stop decoding at end of table marker */
		if (h.type == 127)
			break;

		/* look for the next handle */
		next = data + h.length;
		while (next - buf + 1 < len && (next[0] != 0 || next[1] != 0))
			next++;
		next += 2;

		if (1 == h.type)
		{
			return dmi_system_uuid(data + 8, ver);
		}

		data = next;
		i++;
	}
	return NULL;
}

static char* GetWinSystemUUI()
{
	PRawSMBIOSData smb = get_raw_smbios_table();
	if (smb == NULL)
		return NULL;
	int num_structures = count_smbios_structures(&smb->SMBIOSTableData[0], smb->Length);
	//shows the smbios information
	char* szUUID = dmi_table_frombuf(smb->Length, num_structures, (smb->SMBIOSMajorVersion << 8) + smb->SMBIOSMinorVersion, &smb->SMBIOSTableData[0]);
	free(smb);
	return szUUID;
}

char* vm_uuid()
{
	return GetWinSystemUUI();
}