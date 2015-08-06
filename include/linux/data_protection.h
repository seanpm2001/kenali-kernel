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

static inline size_t kdp_get_shadow_offset(size_t size) {
	if (size <= 312)
		return SZ_4K;
	else if (size <= 656)
		return SZ_8K;
	else if (size <= 1088)
		return SZ_16K;
	else
		return SZ_32K;
}

void atomic_memset_shadow(void *dest, int c, size_t count, size_t alloc_size);
void atomic_memcpy_shadow(void *dest, const void *src, size_t count, size_t alloc_size);
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
