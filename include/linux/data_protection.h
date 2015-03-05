#ifndef LINUX_DATA_PROTECTION_H
#define LINUX_DATA_PROTECTION_H

#include <linux/mm_types.h>
#include <linux/types.h>

#ifdef CONFIG_DATA_PROTECTION
extern int kdp_enabled;

void kdp_enable();
void kdp_protect_page(struct page *page);

#else
#define kdp_enabled 0

static inline void kdp_enable() { }
static inline void kdp_protect_page(struct page *page) { }

#endif /* CONFIG_DATA_PROTECTION */

#endif
