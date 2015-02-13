#ifndef LINUX_DATA_PROTECTION_H
#define LINUX_DATA_PROTECTION_H

#include <linux/mm_types.h>
#include <linux/types.h>

#ifdef CONFIG_DATA_PROTECTION

void kdp_protect_page(struct page *p);
void kdp_unprotect_page(struct page *p);

#else

static inline void kdp_protect_page(struct page *p)
{
}

static inline void kdp_unprotect_page(struct page *p)
{
}

#endif /* CONFIG_DATA_PROTECTION */

#endif
