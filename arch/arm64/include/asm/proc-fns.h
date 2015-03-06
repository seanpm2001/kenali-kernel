/*
 * Based on arch/arm/include/asm/proc-fns.h
 *
 * Copyright (C) 1997-1999 Russell King
 * Copyright (C) 2000 Deep Blue Solutions Ltd
 * Copyright (C) 2012 ARM Ltd.
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
#ifndef __ASM_PROCFNS_H
#define __ASM_PROCFNS_H

#ifdef __KERNEL__
#ifndef __ASSEMBLY__

#include <asm/page.h>

struct mm_struct;
struct cpu_suspend_ctx;

extern void cpu_cache_off(void);
extern void cpu_do_idle(void);
extern void cpu_do_switch_mm(unsigned long pgd_phys, struct mm_struct *mm);
extern void cpu_do_switch_mm_with_asid(unsigned long pgd_phys, unsigned int asid);
extern void cpu_reset(unsigned long addr) __attribute__((noreturn));
extern void cpu_do_suspend(struct cpu_suspend_ctx *ptr);
extern u64 cpu_do_resume(phys_addr_t ptr, u64 idmap_ttbr);
extern void cpu_do_write_shadow(unsigned long addr, unsigned long value, unsigned long shadow_pgd);

#include <asm/memory.h>

#ifdef CONFIG_DATA_PROTECTION
#define cpu_switch_mm(pgd,mm)				\
({							\
	BUG_ON((mm->context.id & 0xffff) == 0);		\
	cpu_do_switch_mm(virt_to_phys(pgd),mm);		\
})
#else
#define cpu_switch_mm(pgd,mm) cpu_do_switch_mm(virt_to_phys(pgd),mm)
#endif

#define cpu_get_pgd()					\
({							\
	unsigned long pg;				\
	asm("mrs	%0, ttbr0_el1\n"		\
	    : "=r" (pg));				\
	pg &= ~0xffff000000003ffful;			\
	(pgd_t *)phys_to_virt(pg);			\
})

#define cpu_switch_mm_with_asid(pgd,asid) cpu_do_switch_mm_with_asid(virt_to_phys(pgd),asid)

#if 0
#define cpu_write_shadow(addr,value,spgd) cpu_do_write_shadow(__virt_to_shadow(addr), value, virt_to_phys(spgd))
#else
#define cpu_write_shadow(addr,value,spgd)		\
({							\
	unsigned long sa = __virt_to_shadow(addr);	\
	unsigned long pgd = virt_to_phys(spgd);		\
	asm("mrs	x3, ttbr0_el1\n"		\
		"msr	ttbr0_el1, %2\n"		\
		"isb	\n"				\
		"str	%1, [%0]\n"			\
		"dsb	ishst\n"			\
		"msr	ttbr0_el1, x3\n"		\
		"isb"					\
		: : "r"(sa), "r"(value), "r"(pgd)	\
		: "%x3");				\
})
#endif

#endif /* __ASSEMBLY__ */
#endif /* __KERNEL__ */
#endif /* __ASM_PROCFNS_H */
