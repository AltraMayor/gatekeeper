/*
 * Gatekeeper - DoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <elf.h>

#include "gatekeeper_cps.h"
#include "elf.h"

#if __WORDSIZE == 32
#define ElfPERBIT(x) Elf32_##x
#else
#define ElfPERBIT(x) Elf64_##x
#endif

struct elf_file {
	/* File contents. */
	const void    *data;

	/* Length of file contents. */
	unsigned long len;

	/* Whether the endianness needs to be converted. */
	int           conv;
};

/*
 * Get CPU endianness.
 *
 * 1 = ELFDATA2LSB = little
 * 2 = ELFDATA2MSB = big
 */
static int __attribute__((pure))
native_endianness(void)
{
	/*
	 * Encoding the endianness enums in a string
	 * and then reading that string as a 16-bit integer.
	 */
	return (char)*((const uint16_t *)("\1\2"));
}

static inline void
__swap_bytes(const void *src, void *dest, unsigned int size)
{
	unsigned int i;
	for (i = 0; i < size; i++) {
		((unsigned char *)dest)[i] =
			((const unsigned char *)src)[size - i - 1];
	}
}

/* Change endianness of @x if @conv is true storing it in @buf_ptr. */
#define END(x, conv, buf_ptr)						\
({									\
	if (conv) __swap_bytes(&(x), (buf_ptr), sizeof(*buf_ptr));	\
	else *(buf_ptr) = (x);						\
})

/* Get the section specified in @secname from the ELF file. */
static const void *
get_section(const struct elf_file *mod, const char *secname,
	unsigned long *secsize)
{
	unsigned long len = mod->len;
	int conv = mod->conv;
	unsigned int i;
	const char *secstrings;

	const ElfPERBIT(Ehdr) *hdr = mod->data;
	const ElfPERBIT(Shdr) *sechdrs;
	ElfPERBIT(Off) e_shoff_ntv;
	ElfPERBIT(Half) e_shnum_ntv;
	ElfPERBIT(Half) e_shstrndx_ntv;
	ElfPERBIT(Off) sh_offset_ntv;
	ElfPERBIT(Word) sh_size_ntv;

	*secsize = 0;

	/* Check whether there's enough room for ELF header. */
	if (len < sizeof(*hdr))
		return NULL;

	/* Read in necessary variables from ELF header and fix endianness. */
	END(hdr->e_shoff, conv, &e_shoff_ntv);
	END(hdr->e_shnum, conv, &e_shnum_ntv);
	END(hdr->e_shstrndx, conv, &e_shstrndx_ntv);

	/* Check whether there's enough room for the section headers. */
	if (len < e_shoff_ntv + e_shnum_ntv * sizeof(sechdrs[0]))
		return NULL;

	sechdrs = (const ElfPERBIT(Shdr) *)
		((const uint8_t *)hdr + e_shoff_ntv);

	/* Check whether there's enough room for section with section names. */
	END(sechdrs[e_shstrndx_ntv].sh_offset, conv, &sh_offset_ntv);
	END(sechdrs[e_shstrndx_ntv].sh_size, conv, &sh_size_ntv);
	if (len < sh_offset_ntv + sh_size_ntv)
		return NULL;

	/* Find symbol table. */
	secstrings = (const char *)((const uint8_t *)hdr + sh_offset_ntv);
	if (sh_size_ntv <= 0 || secstrings[sh_size_ntv - 1] != '\0')
		return NULL;

	/* First section (index 0) in ELF files is reserved as undefined. */
	for (i = 1; i < e_shnum_ntv; i++) {
		ElfPERBIT(Word) sh_name_ntv;
		const char *found_secname;

		END(sechdrs[i].sh_name, conv, &sh_name_ntv);
		if (sh_name_ntv >= sh_size_ntv) {
			/*
			 * Malformed section. Skipping it to
			 * see if we can still find @secname.
			 */
			continue;
		}
		found_secname = secstrings + sh_name_ntv;

		if (strcmp(secname, found_secname) == 0) {
			END(sechdrs[i].sh_size, conv, &sh_size_ntv);
			END(sechdrs[i].sh_offset, conv, &sh_offset_ntv);

			/* Not enough room in file for this section. */
			if (len < sh_offset_ntv + sh_size_ntv)
				return NULL;

			*secsize = sh_size_ntv;
			return (const uint8_t *)hdr + sh_offset_ntv;
		}
	}

	return NULL;
}

/* Find the next string in an ELF section. */
static const char *
next_string(const char *string, unsigned long *secsize)
{
	if (*secsize == 0)
		return NULL;

	/* Skip non-zero chars. */
	while (string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}

	/* Skip any zero padding. */
	while (!string[0]) {
		string++;
		if ((*secsize)-- <= 1)
			return NULL;
	}

	return string;
}

static int
load_string(const struct elf_file *mod, const char *attr,
	char *val, size_t val_len)
{
	unsigned long secsize;
	size_t attr_len;
	const char *strings;

	/* Get strings from modinfo section. */
	strings = get_section(mod, ".modinfo", &secsize);
	if (strings == NULL) {
		CPS_LOG(ERR, "Unable to get modinfo section from kernel module\n");
		return -1;
	}

	if (secsize == 0) {
		CPS_LOG(ERR, "Returned modinfo section is of length 0\n");
		return -1;
	}

	if (strings[secsize - 1] != '\0') {
		CPS_LOG(ERR, "An unterminated string was found at the end of the modinfo section\n");
		return -1;
	}

	/* Skip any zero padding. */
	while (!strings[0]) {
		strings++;
		if (secsize-- <= 1)
			return -1;
	}

	attr_len = strlen(attr);
	while (strings != NULL) {
		/* Find line with attribute followed by '='. */
		if (strncmp(strings, attr, attr_len) == 0 &&
				strings[attr_len] == '=') {
			strings += attr_len + 1;
			if (strlen(strings) > val_len - 1) {
				CPS_LOG(ERR, "Found attribute %s in modinfo but value buffer is too short to read in its value (%s)\n",
					attr, strings);
				return -1;
			}

			/* Copy starting from after the '='. */
			strcpy(val, strings);
			return 0;
		}

		strings = next_string(strings, &secsize);
	}

	return -1;
}

/* Check ELF file header. */
static int
elf_ident(const void *file, unsigned long len, int *conv)
{
	/* ELFMAG <byte> where byte = 001 for 32-bit, 002 for 64. */
	const unsigned char *ident = file;

	if (len < EI_CLASS || memcmp(file, ELFMAG, SELFMAG) != 0) {
		/* Not an ELF object. */
		return -ENOEXEC;
	}

	if (ident[EI_DATA] == 0 || ident[EI_DATA] > 2) {
		/* Unknown endianness. */
		return -EINVAL;
	}

	if (conv != NULL)
		*conv = native_endianness() != ident[EI_DATA];

	return ident[EI_CLASS];
}

int
get_modinfo_string(const void *file, unsigned long len, const char *attr,
	char *val, size_t val_len)
{
	struct elf_file mod;
	int elf_type = elf_ident(file, len, &mod.conv);
	int ret;

	if (elf_type != ELFCLASS32 && elf_type != ELFCLASS64) {
		CPS_LOG(ERR, "Unable to read kernel module header for attribute %s\n",
			attr);
		return -1;
	}

	mod.data = file;
	mod.len = len;

	ret = load_string(&mod, attr, val, val_len);
	if (ret < 0) {
		CPS_LOG(ERR, "Unable to find %s in modinfo section of kernel module\n",
			attr);
	}

	return ret;
}
