/*
 * Copyright (C) 2014-2016 Chengyu Song
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LINUX_DATA_PROTECTION_H
#define LINUX_DATA_PROTECTION_H

#include <linux/mm_types.h>
#include <linux/types.h>

#ifdef CONFIG_DATA_PROTECTION
extern int kdp_enabled;

void kdp_enable();
void kdp_protect_page(struct page *page);
void kdp_unprotect_page(struct page *page);
void kdp_protect_init_page(void* address);
void *kdp_map_stack(struct page *page);
void *kdp_unmap_stack(void *addr);
struct page *kdp_get_stack_page(void *stack);
void kdp_alloc_shadow(struct page *page, int order, gfp_t flags, int node);
void kdp_free_shadow(struct page *page, int order);

void atomic_memset_shadow(void *dest, int c, size_t count);
void atomic_memcpy_shadow(void *dest, const void *src, size_t count);
void atomic64_write_shadow(unsigned long *addr, unsigned long value);
void atomic32_write_shadow(unsigned *addr, unsigned value);
void atomic16_write_shadow(unsigned short *addr, unsigned short value);
void atomic8_write_shadow(unsigned char *addr, unsigned char value);

#else
#define kdp_enabled 0

static inline void kdp_enable() { }
static inline void kdp_protect_page(struct page *page) { }
static inline void kdp_unprotect_page(struct page *page) { }
static inline void kdp_protect_init_page(void* address) { }
static inline void *kdp_map_stack(struct page *page)
{
	return page ? page_address(page) : NULL;
}
static inline void *kdp_unmap_stack(void *addr)
{
	return addr;
}

#endif /* CONFIG_DATA_PROTECTION */

#endif
