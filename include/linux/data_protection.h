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

void atomic_memcpy_shadow(void *dest, const void *src, size_t count);
void atomic64_write_shadow(unsigned long *addr, unsigned long value);
void atomic32_write_shadow(unsigned long *addr, unsigned value);
void atomic16_write_shadow(unsigned long *addr, unsigned short value);
void atomic8_write_shadow(unsigned long *addr, unsigned char value);

#else
#define kdp_enabled 0

static inline void kdp_enable() { }
static inline void kdp_protect_page(struct page *page) { }
static inline void kdp_unprotect_page(struct page *page) { }
static inline void kdp_protect_init_page(void* address) { }

#endif /* CONFIG_DATA_PROTECTION */

#endif
