#ifndef LINUX_DATA_PROTECTION_H
#define LINUX_DATA_PROTECTION_H

#include <linux/mm_types.h>
#include <linux/types.h>

#ifdef CONFIG_DATA_PROTECTION

void kdp_protect_page(unsigned long address);

#else

static inline void kdp_protect_page(unsigned long address)
{
}

#endif /* CONFIG_DATA_PROTECTION */

#endif
