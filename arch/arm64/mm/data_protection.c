#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/data_protection.h>

#include <asm/sections.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/proc-fns.h>
#include <asm/tlbflush.h>

//#define SOBJ_START ((void*)_etext)
//#define SOBJ_START ((void*)_edata)

#define DEBUG_SOBJ

int kdp_enabled __section(.rodata);

#define SOBJ_START (PAGE_OFFSET + SZ_2G)
#define KDP_STACK_START (PAGE_OFFSET + SZ_4G)

struct kdp_stack_mapping {
	void *addr;
	void *rand_addr;
};
#define KDP_STACK_MAP_SIZE 4096
struct kdp_stack_mapping kdp_stack_map[KDP_STACK_MAP_SIZE] __section(.kdp_secret);
static DEFINE_SPINLOCK(kdp_stack_map_lock);

#define KDP_STACK_MAP_START	((void*)kdp_stack_map)
#define KDP_STACK_MAP_END	((void*)&kdp_stack_map[KDP_STACK_MAP_SIZE-1])

static pmdval_t prot_sect_shadow;

enum pg_level {
	PG_LEVEL_NONE,
	PG_LEVEL_4K,
	PG_LEVEL_2M,
	PG_LEVEL_1G,
	PG_LEVEL_NUM
};

int __init kdp_init(void)
{
	struct memblock_region *reg;
	phys_addr_t phys, size = 0;
	unsigned long shadow, addr, length, end, pgd_next, pmd_next;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t *next_reserved_pmd = (pmd_t *)(shadow_pg_dir + PTRS_PER_PGD);
	pmdval_t prot_sect_shadow;

	prot_sect_shadow = PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_NG | PMD_ATTRINDX(MT_NORMAL);
	prot_sect_shadow |= PMD_SECT_PXN | PMD_SECT_UXN;
#ifdef CONFIG_SMP
	prot_sect_shadow |= PMD_SECT_S;
#endif

	memset(shadow_pg_dir, 0, SHADOW_DIR_SIZE);

	/*
	 * try to map all physical memory banks
	 * FIXME: use early alloc to handle arbitrary size
	 */
	for_each_memblock(memory, reg) {
		phys = reg->base;
		size += reg->size;

		if (size > SHADOW_MEM_SIZE) {
			pr_warning("BUG: physical memory size (0x%llx) larger than reserved shadow memory size (0x%lx)\n",
					size, SHADOW_MEM_SIZE);
			break;
		}

		shadow = __phys_to_shadow(phys);
		addr = shadow & PAGE_MASK;
		length = PAGE_ALIGN(reg->size + (shadow & ~PAGE_MASK));

		pgd = pgd_offset_s(addr);
		end = addr + length;

		pr_info("KDFI: maping shadow address 0x%016lx - 0x%016lx\n", addr, end);
		do {
			pgd_next = pgd_addr_end(addr, end);
			pud = pud_offset(pgd, addr);
			if (pud_none(*pud)) {
				pmd = next_reserved_pmd;
				pr_info("KDFI: alloc reserved pmd = 0x%016llx\n", __pa(pmd));
				set_pud(pud, __pud(__pa(pmd) | PMD_TYPE_TABLE));
				next_reserved_pmd += PTRS_PER_PMD;
			}

			pmd = pmd_offset(pud, addr);
			do {
				pmd_next = pmd_addr_end(addr, pgd_next);
				set_pmd(pmd, __pmd(phys | prot_sect_shadow));
				phys += pmd_next - addr;
			} while (pmd++, addr = pmd_next, addr != pgd_next);

		} while (pgd++, addr != end);
	}

	return 0;
}

early_initcall(kdp_init);

static void protect_kernel(void)
{
	unsigned long addr, end, pgd_next, pmd_next;
	unsigned long code_start, code_end;
	unsigned long ro_start, ro_end;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ppte;
	pte_t pte;

	/* first, determine code section range */
	code_start = (unsigned long)_text;
	code_end = (unsigned long)__start_rodata;

	/* then, find rodata section range */
	ro_start = (unsigned long)__start_rodata;
	ro_end = (unsigned long)_etext;

	pr_info("KDFI: mark kernel code section (0x%16lx - 0x%016lx) as RX\n",
			code_start, code_end);
	pr_info("KDFI: mark kernel rodata section (0x%16lx - 0x%016lx) as RO\n",
			ro_start, ro_end);
	pr_info("KDFI: kernel end = 0x%p\n", _end);

	addr = VMALLOC_START;
	end = UL(0xffffffffffffffff) & PAGE_MASK;

	pgd = pgd_offset_k(addr);
	do {
		pgd_next = pgd_addr_end(addr, end);
		pud = pud_offset(pgd, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			continue;

		pmd = pmd_offset(pud, addr);
		do {
			pmd_next = pmd_addr_end(addr, pgd_next);
			if(pmd_none(*pmd) || pmd_bad(*pmd))
				continue;
			
			ppte = pte_offset_kernel(pmd, addr);
			do {
				if (!pte_present(*ppte))
					continue;

				if (addr >= code_start && addr < code_end)
					pte = pte_modify(*ppte, PAGE_KERNEL_READONLY_EXEC);
				else if (addr >= ro_start && addr < ro_end)
					pte = pte_modify(*ppte, PAGE_KERNEL_READONLY);
				else
					pte = pte_modify(*ppte, PAGE_KERNEL);

				set_pte(ppte, pte);
			} while (ppte++, addr += PAGE_SIZE, addr != pmd_next);
		
		} while (pmd++, addr = pmd_next, addr != pgd_next);
	
	} while (pgd++, addr = pgd_next, addr != end);				
}

static pte_t *lookup_address(unsigned long address, unsigned int *level)
{
	pgd_t *pgd = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;

	*level = PG_LEVEL_NONE;

	pgd = pgd_offset_k(address);
	pud = pud_offset(pgd, address);
	if (unlikely(pud_none(*pud)))
		return NULL;

	*level = PG_LEVEL_1G;
	/* This should never happen */
	if (unlikely(pud_bad(*pud)))
		return (pte_t *)pud;

	pmd = pmd_offset(pud, address);
	if (unlikely(pmd_none(*pmd)))
		return NULL;

	*level = PG_LEVEL_2M;
	/* This should never happen */
	if (unlikely(pmd_bad(*pmd)))
		return (pte_t *)pmd;

	*level = PG_LEVEL_4K;
	pte = pte_offset_kernel(pmd, address);

	return pte;
}

static void inline flush_kern_tlb_one_page(void* address)
{
	asm (
	"	dsb	ishst\n"
	"	lsr	%0, %0, #12\n"
	"	tlbi	vaale1is, %0\n"
	"	dsb	ish\n"
	"	isb"
	: : "r" (address));
}

#define KDP_INIT_PAGE_LIST 4096
struct kdp_init_page_item {
	void* addr;
	pgprot_t prot;
};
static struct kdp_init_page_item kdp_init_page_list[KDP_INIT_PAGE_LIST] __initdata = {};
static unsigned kdp_init_page_list_head = 0;

static void _kdp_protect_init_page(void* address, pgprot_t prot) {

	//pr_info("KDFI: enqueue page %p\n", address);

	if (unlikely(kdp_init_page_list_head >= KDP_INIT_PAGE_LIST)) {
		pr_err("KDFI: list size too small %d\n", kdp_init_page_list_head++);
		return;
	}

	kdp_init_page_list[kdp_init_page_list_head].addr = address;
	kdp_init_page_list[kdp_init_page_list_head].prot = prot;
	kdp_init_page_list_head++;
}

void kdp_protect_init_page(void *address)
{
	_kdp_protect_init_page(address, PAGE_KERNEL_READONLY);
}

static void _kdp_protect_one_page(void* address, pgprot_t prot)
{
	pte_t *ptep, pte;
	unsigned int level;

	if (unlikely(address == NULL))
		return;

	ptep = lookup_address((unsigned long)address, &level);
	BUG_ON(!ptep);
	BUG_ON(level != PG_LEVEL_4K);

	pte = pte_modify(*ptep, prot);
	if (unlikely(pte == *ptep))
		return;

	if (likely(kdp_enabled)) {
		set_pte(ptep, pte);
		flush_kern_tlb_one_page(address);
	} else {
		set_pte(virt_to_shadow(ptep), pte);
	}
}

void kdp_protect_one_page(void *address)
{
	_kdp_protect_one_page(address, PAGE_KERNEL_READONLY);
}

void kdp_unprotect_one_page(void* address)
{
	pte_t *ptep, pte;
	unsigned int level;

	if (unlikely(address == NULL))
		return;

	if (unlikely(!kdp_enabled)) {
		pr_err("KDFI not enabled\n");
		return;
	}

	ptep = lookup_address((unsigned long)address, &level);
	BUG_ON(!ptep);
	BUG_ON(level != PG_LEVEL_4K);

	pte = pte_modify(*ptep, PAGE_KERNEL);
	set_pte(ptep, pte);
	flush_kern_tlb_one_page(address);
}

static void protect_pgtable(pgd_t *pg_dir)
{
	/* 
	 * traverse the whole page table and 
	 * make every page translation struct as read-only
	 * under direct mapping
	 */
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pt;
	phys_addr_t phys;
	int i, j;

	/* first, protect the page directory page */
	kdp_protect_one_page(pg_dir);

	for (i = 0; i < PTRS_PER_PGD; i++) {
		/* collapse pgd and pud for now */
		pud = (pud_t *)&pg_dir[i];

		if (pud_none(*pud))
			continue;

		/* second, protect valid pmd pages */
		pmd = pud_page_vaddr(*pud);
		kdp_protect_one_page(pmd);
		
		for (j = 0; j < PTRS_PER_PMD; j++) {
			/* skip sections as well */
			if (pmd_none(pmd[j]) || pmd_bad(pmd[j]))
				continue;

			/* finally, protect valid pte pages */
			pt = pmd_page_vaddr(pmd[j]);
			kdp_protect_one_page(pt);
		}
	}
}

static void context_switch_test()
{
	unsigned long pgd = virt_to_phys(shadow_pg_dir);
	unsigned long flags;
	unsigned long start, end;
	unsigned pmcr, pmcntenset;

	/* enable counter */
	asm volatile("mrs %0, pmcr_el0" : "=r" (pmcr));
	pr_info("KDFI: pmcr = %08x\n", pmcr);

	asm volatile("mrs %0, pmcntenset_el0" : "=r" (pmcntenset));
	asm volatile(
	"	isb\n"
	"	msr pmcr_el0, %0\n"
	"	msr pmcntenset_el0, %1\n"
	"	isb\n"
	: : "r" (pmcr | 0x5), "r" (pmcntenset | 0x80000000));

	flags = arch_local_irq_save();
	asm volatile("mrs %0, pmccntr_el0" : "=r" (start));

	for(int i = 0; i < 1000000; i++) {
		asm volatile(
		"	mrs	x3, ttbr0_el1\n"
		"	msr	ttbr0_el1, %0\n"
		"	isb	\n"
		//"	dmb	ishst\n"
		"	msr	ttbr0_el1, x3\n"
		"	isb	\n"
		: : "r" (pgd)
		: "x3", "memory");
	}

	asm volatile("mrs %0, pmccntr_el0" : "=r" (end));
	arch_local_irq_restore(flags);

	/* restore */
	asm volatile(
	"	isb\n"
	"	msr pmcr_el0, %0\n"
	"	msr pmcntenset_el0, %1\n"
	"	isb\n"
	: : "r" (pmcr), "r" (pmcntenset));

	pr_info("KDFI: context switch, start = %ld, end = %ld, result = %ld\n",
		start, end, end - start);
}

void kdp_map_global_shadow();
void kdp_enable(void)
{
	pgd_t* old_pg = cpu_get_pgd();
	pr_info("KDFI: old pgd = 0x%p, zero page = 0x%lx\n",
		old_pg, empty_zero_page);

	//context_switch_test();
	kdp_map_global_shadow();
	protect_kernel();

	/*
	 * enable shadow page table, this is necessary for
	 * making swapper_pg_dir as read-only
	 */
	cpu_switch_mm_with_asid(shadow_pg_dir, 0);

	/* protect all init page tables */
	protect_pgtable(idmap_pg_dir);
	protect_pgtable(shadow_pg_dir);
	protect_pgtable(swapper_pg_dir);

	pr_info("KDFI: init pages = %d\n", kdp_init_page_list_head);
	/* protect enqueued pages */
	for (unsigned i = 0; i < kdp_init_page_list_head; i++) {
		_kdp_protect_one_page(kdp_init_page_list[i].addr,
				kdp_init_page_list[i].prot);
	}

	/* FIXME gone through kdp_stack_map and protect stack page */

	/* set data protection as enabled */
	*((int *)(virt_to_shadow(&kdp_enabled))) = 1;

	/* restore old pgd */
	cpu_switch_mm_with_asid(old_pg, 0);
	flush_tlb_all();
}

void kdp_protect_page(struct page *page)
{
	int order;
	void *address;
	int i, start, end;

	if (unlikely((page == NULL)))
		return;

	order = compound_order(page);
	if (unlikely(order == 0)) {
		pr_warning("KDFI: page order < 1\n");
		return;
	}
	start = 1 << (order - 1);
	end = 1 << order;

	for (i = start; i < end; ++i) {
		address = page_address(&page[i]);
		//pr_info("KDFI: protect page 0x%p\n", address);
#ifndef DEBUG_SOBJ
		if (likely(kdp_enabled))
			kdp_protect_one_page(address);
		else
			kdp_protect_init_page(address);
#endif
	}
}

void kdp_unprotect_page(struct page *page)
{
	int order;
	void *address;
	int i, start, end;

	if (unlikely(page == NULL))
		return;

	order = compound_order(page);
	if (unlikely(order == 0)) {
		pr_warning("KDFI: page order < 1\n");
		return;
	}
	start = 1 << (order - 1);
	end = 1 << order;

#ifndef DEBUG_SOBJ
	for (i = start; i < end; ++i) {
		address = page_address(&page[i]);
		//pr_info("KDFI: unprotect page 0x%p\n", address);
		if (likely(kdp_enabled))
			kdp_unprotect_one_page(address);
		else
			pr_warning("KDFI: unprotect called when kdp is not enabled\n");
	}
#endif
}

static void kdp_unmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);

#if 0
	pte = pmd_page_vaddr(*pmd);
	int pte_count = 0;
	for (int i = 0; i < PTRS_PER_PTE; i++)
		pte_count += !!pte_val(pte[i]);
	/* free likely empty pte */
	if (likely(!pte_count))
		pte_free_kernel(&init_mm, pte);
#endif
}

static void kdp_unmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		kdp_unmap_pte_range(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);

	//pmd = pmd_offset(pud, addr);
	//pmd_free(&init_mm, pmd);
}

static void kdp_unmap_pud_range(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		kdp_unmap_pmd_range(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

static void kdp_unmap_page_range(unsigned long addr, unsigned long end)
{
	pgd_t *pgd;
	unsigned long next;

	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		kdp_unmap_pud_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

static int kdp_map_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			     struct page *page, int *nr)
{
	pte_t *pte;

	pte = pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		struct page *target = &page[*nr];

		if (WARN_ON(!pte_none(*pte)))
			return -EBUSY;
		if (WARN_ON(!page))
			return -ENOMEM;
		set_pte_at(&init_mm, addr, pte, mk_pte(target, PAGE_KERNEL));
		(*nr)++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	
	return 0;
}

static int kdp_map_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
			     struct page *page, int *nr)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	pmd = pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		err = kdp_map_pte_range(pmd, addr, next, page, nr);
		if (err)
			return err;
	} while (pmd++, addr = next, addr != end);

	return 0;
}

static int kdp_map_pud_range(pgd_t *pgd, unsigned long addr, unsigned long end,
			     struct page *page, int *nr)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pud = pud_alloc(&init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		err = kdp_map_pmd_range(pud, addr, next, page, nr);
		if (err)
			return err;
	} while (pud++, addr = next, addr != end);

	return 0;
}

static int kdp_map_page_range(unsigned long start, unsigned long end,
			      struct page *page, int *nr)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = start;
	int err = 0;

	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = kdp_map_pud_range(pgd, addr, next, page, nr);
		if (err)
			return err;
	} while (pgd++, addr = next, addr != end);

	return 0;
}

void *kdp_get_real_stack(void *stack)
{
	if (likely(stack >= KDP_STACK_MAP_START &&
		   stack <= KDP_STACK_MAP_END))
		return ((struct kdp_stack_mapping*)stack)->rand_addr;
	return stack;
}

struct page *kdp_get_stack_page(void *stack)
{
	if (likely(stack >= KDP_STACK_MAP_START &&
		   stack <= KDP_STACK_MAP_END))
		return ((struct kdp_stack_mapping*)stack)->addr;
	return stack;
}

static int kdp_set_real_stack(void *real_stack, void *rand_stack)
{
	/* FIXME replace linear search with better ones */
	int i;

	spin_lock(&kdp_stack_map_lock);
	for (i = 0; i < KDP_STACK_MAP_SIZE; i++) {
		if (kdp_stack_map[i].addr == NULL) {
			kdp_stack_map[i].addr = real_stack;
			kdp_stack_map[i].rand_addr = rand_stack;
			break;
		}
	}
	spin_unlock(&kdp_stack_map_lock);

	WARN_ON(i == KDP_STACK_MAP_SIZE);
	return i;
}

void *kdp_map_stack(struct page *page)
{
	unsigned long start, addr, end, range, random;
	void *page_addr;
	int nr = 0;
	int err;

	if (unlikely(!page))
		return NULL;

	/* FIXME should be the end of physical memory
	 * currently use 4G, as most devices have less than 4G memory */
	start = KDP_STACK_START;
	range = 0xffffffffffffffffULL - start - THREAD_SIZE;

try_again:
	/* FIXME should use tree like structure to maintain mapped
	 * addresses, currently uses a re-try based approach,
	 * assuming randomized stack are unlikely to overlap */
	get_random_bytes(&random, sizeof(random));
	addr = ALIGN(random % (range + 1) + start, PAGE_SIZE << THREAD_SIZE_ORDER);
	end = addr + THREAD_SIZE;
	/* in case overflows due to alignment */
	while (addr >= end) {
		addr -= PAGE_SIZE << THREAD_SIZE_ORDER;
		end = addr + THREAD_SIZE;
	}

	err = kdp_map_page_range(addr, end, page, &nr);
	if (unlikely(err)) {
		if (nr > 0) {
			end = addr + PAGE_SIZE * nr;
			kdp_unmap_page_range(addr, end);
		}

		/* overlapping */
		if (err == -EBUSY)
			goto try_again;

		return NULL;
	}

	page_addr = page_address(page);
	int index = kdp_set_real_stack(page_addr, (void *)addr);
	//pr_info("KDFI: map stack at %lx, slot = %d, slot addr = %p\n",
	//		addr, index, &kdp_stack_map[index]);
	flush_tlb_kernel_range(addr, end);

	WARN_ON(nr != THREAD_SIZE/PAGE_SIZE);

	/* mark page as inaccessible */
#if 0
	if (likely(kdp_enabled)) {
		for (int i = 0; i < nr; i++)
			_kdp_protect_one_page(page_addr + i * PAGE_SIZE, PAGE_NONE);
	}
#endif

	return &kdp_stack_map[index];
}

void *kdp_unmap_stack(void *addr)
{
	unsigned long start = 0, end;
	struct kdp_stack_mapping *map;
	void *p_addr;

	spin_lock(&kdp_stack_map_lock);
	if (likely(addr >= KDP_STACK_MAP_START &&
		   addr <= KDP_STACK_MAP_END)) {
		map = (struct kdp_stack_mapping*)addr;
		start = (unsigned long)map->rand_addr;
		p_addr = addr = map->addr;
		map->addr = NULL;
	}
	spin_unlock(&kdp_stack_map_lock);

	if (unlikely(!start))
		return addr;

	end = start + THREAD_SIZE;
	//pr_info("KDFI: unmap stack %lx - %lx\n", start, end);
	kdp_unmap_page_range(start, end);
	flush_tlb_kernel_range(start, end);

	end = (unsigned long)addr + THREAD_SIZE;
	if (likely(kdp_enabled)) {
		do {
			kdp_unprotect_one_page(addr);
		} while (addr += PAGE_SIZE, (unsigned long)addr != end);
	}

	return p_addr;
}

void kdp_map_global_shadow()
{
	unsigned long start, end, size;
	struct page *page, *shadow;
	void *address;
	int order, pages;
	int i, nr = 0;
	int err;

	start = (unsigned long)(_sdata);
	end = PAGE_ALIGN((unsigned long)(_edata));
	size = end - start;
	pages = size >> PAGE_SHIFT;
	size = __roundup_pow_of_two(size);
	order = size >> PAGE_SHIFT - 1;

	pr_info("KDFI: round up data section to %lx\n", size);

	shadow = alloc_pages(GFP_KERNEL | __GFP_NOTRACK, order);
	if (!shadow) {
		pr_err("KDFI: failed to allocate shadow for global\n");
		return;
	}

	/* map shadow */
	err = kdp_map_page_range(start, start + size, shadow, &nr);
	if (unlikely(err)) {
		pr_err("KDFI: failed to map shadow\n");
		__free_pages(shadow, order);
		return;
	}

	for (i = 0; i < pages; ++i) {
		address = page_address(&shadow[i]);
		page[i].kdp_shadow = address;
		memcpy(address, page_address(&page[i]), PAGE_SIZE);
#ifndef DEBUG_SOBJ
		if (likely(kdp_enabled))
			kdp_protect_one_page(address);
		else
			kdp_protect_init_page(address);
#endif
	}
}

void kdp_alloc_shadow(struct page *page, int order, gfp_t flags, int node)
{
	unsigned long start, end;
	struct page *shadow;
	void *address;
	int pages;
	int i, nr = 0;
	int err;

	pages = 1 << order;

	shadow = alloc_pages_node(node, flags | __GFP_NOTRACK, order);
	if (!shadow) {
		pr_err("KDFI: failed to allocate shadow\n");
		return;
	}

	/* map shadow */
	start = (unsigned long)page_address(page) + SZ_2G;
	end = start + pages * PAGE_SIZE;

	err = kdp_map_page_range(start, end, shadow, &nr);
	if (unlikely(err)) {
		pr_err("KDFI: failed to map shadow\n");
		__free_pages(shadow, order);
		return;
	}

	for (i = 0; i < pages; ++i) {
		address = page_address(&shadow[i]);
		page[i].kdp_shadow = address;
#ifndef DEBUG_SOBJ
		if (likely(kdp_enabled))
			kdp_protect_one_page(address);
		else
			kdp_protect_init_page(address);
#endif
	}
}

void kdp_free_shadow(struct page *page, int order)
{
	unsigned long start, end;
	struct page *shadow;
	void *address;
	int pages;
	int i, nr = 0;
	int err;

	pages = 1 << order;

	/* unmap shadow */
	start = (unsigned long)page_address(page) + SZ_2G;
	end = start + pages * PAGE_SIZE;

	kdp_unmap_page_range(start, end);
	flush_tlb_kernel_range(start, end);

	shadow = virt_to_page(page[0].kdp_shadow);

	for (i = 0; i < pages; ++i) {
		address = page_address(&shadow[i]);
		page[i].kdp_shadow = NULL;
#ifndef DEBUG_SOBJ
		kdp_unprotect_one_page(address);
#endif
	}

	__free_pages(shadow, order);
}

void atomic_memset_shadow(void *dest, int c, size_t count, size_t alloc_size)
{
	struct page *page;
	void *sdest = NULL;

	if (likely((unsigned long)dest > PAGE_OFFSET &&
	           (unsigned long)dest < KDP_STACK_START)) {
		// has shadow object?
		page = virt_to_page(dest);
		if (page->kdp_shadow)
			sdest = page->kdp_shadow +
				((unsigned long)dest & (PAGE_SIZE - 1));
	}

	if (unlikely(!sdest)) {
		return;
	}

	if (unlikely(!kdp_enabled)) {
		memset(sdest, c, count);
		return;
	}

	sdest = virt_to_shadow(sdest);
	unsigned long pgd = virt_to_phys(shadow_pg_dir);
	unsigned long old_pgd, flags;

	asm volatile(
	"	mrs	%1, daif\n"
	"	msr	daifset, #2\n"
	"	mrs	%0, ttbr0_el1\n"
	"	msr	ttbr0_el1, %2\n"
	"	isb	\n"
	: "=r" (old_pgd), "=r" (flags)
	: "r" (pgd)
	:);

	memset(sdest, c, count);

	asm volatile(
	"	dmb	ishst\n"
	"	msr	ttbr0_el1, %0\n"
	"	isb	\n"
	"	msr	daif, %1\n"
	: : "r" (old_pgd), "r" (flags)
	:);
}

void atomic_memcpy_shadow(void *dest, const void *src, size_t count, size_t alloc_size)
{
	struct page *page;
	void *sdest = NULL;
	const void *ssrc = src;

	if (likely((unsigned long)dest > PAGE_OFFSET &&
	           (unsigned long)dest < KDP_STACK_START)) {
		// has shadow object?
		page = virt_to_page(dest);
		if (page->kdp_shadow)
			sdest = page->kdp_shadow +
				((unsigned long)dest & (PAGE_SIZE - 1));
	}

	if (likely((unsigned long)src > PAGE_OFFSET &&
	           (unsigned long)src < KDP_STACK_START)) {
		page = virt_to_page(src);
		if (page->kdp_shadow)
			ssrc = src + SZ_2G;
	}

	if (unlikely(sdest == NULL)) {
		//memcpy(dest, src, count);
		return;
	}

	if (unlikely(!kdp_enabled)) {
		memcpy(sdest, ssrc, count);
		return;
	}

	sdest = virt_to_shadow(sdest);
	unsigned long pgd = virt_to_phys(shadow_pg_dir);
	unsigned long old_pgd, flags;

	asm volatile(
	"	mrs	%1, daif\n"
	"	msr	daifset, #2\n"
	"	mrs	%0, ttbr0_el1\n"
	"	msr	ttbr0_el1, %2\n"
	"	isb	\n"
	: "=r" (old_pgd), "=r" (flags)
	: "r" (pgd)
	:);

	memcpy(sdest, ssrc, count);

	asm volatile(
	"	dmb	ish\n"
	"	msr	ttbr0_el1, %0\n"
	"	isb	\n"
	"	msr	daif, %1\n"
	: : "r" (old_pgd), "r" (flags)
	:);
}

void atomic64_write_shadow(unsigned long *addr, unsigned long value)
{
	struct page *page;
	void *sa = NULL;

	if (unlikely(!kdp_enabled)) {
		*addr = value;
		return;
	}

#if 1
	if (likely((unsigned long)addr > PAGE_OFFSET &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr);
		if (page->kdp_shadow)
			sa = addr;
	}
#else
	if (likely((unsigned long)addr > SOBJ_START &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr - SZ_2G);
		if (page->kdp_shadow)
			sa = page->kdp_shadow +
				((unsigned long)addr & (PAGE_SIZE - 1));
	}
#endif
	else {
		*addr = value;
		return;
	}

	sa = virt_to_shadow(sa);
	unsigned long pgd = virt_to_phys(shadow_pg_dir);
	unsigned long flags;
	asm volatile(
	"	mrs	x2, daif\n"
	"	msr	daifset, #2\n"
	"	mrs	x3, ttbr0_el1\n"
	"	msr	ttbr0_el1, %2\n"
	"	isb	\n"
	"	str	%1, [%0]\n"
	"	dmb	ishst\n"
	"	msr	ttbr0_el1, x3\n"
	"	isb	\n"
	"	msr	daif, x2\n"
	: : "r" ((unsigned long)sa), "r" (value), "r" (pgd)
	: "x2", "x3", "memory");
}

void atomic32_write_shadow(unsigned *addr, unsigned value)
{
	struct page *page;
	void *sa = NULL;
	static int count = 20;

	if (unlikely(!kdp_enabled)) {
		*addr = value;
		return;
	}

#if 1
	if (likely((unsigned long)addr > PAGE_OFFSET &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr);
		if (page->kdp_shadow)
			sa = addr;
	}
#else
	if (likely((unsigned long)addr > SOBJ_START &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr - SZ_2G);
		if (page->kdp_shadow)
			sa = page->kdp_shadow +
				((unsigned long)addr & (PAGE_SIZE - 1));
	}
#endif
	else {
		*addr = value;
		return;
	}

	sa = virt_to_shadow(sa);
	unsigned long pgd = virt_to_phys(shadow_pg_dir);
	unsigned long flags;
	asm volatile(
	"	mrs	x2, daif\n"
	"	msr	daifset, #2\n"
	"	mrs	x3, ttbr0_el1\n"
	"	msr	ttbr0_el1, %2\n"
	"	isb	\n"
	"	str	%w1, [%0]\n"
	"	dmb	ishst\n"
	"	msr	ttbr0_el1, x3\n"
	"	isb	\n"
	"	msr	daif, x2\n"
	: : "r" ((unsigned long)sa), "r" (value), "r" (pgd)
	: "x2", "x3", "memory");
}

void atomic16_write_shadow(unsigned short *addr, unsigned short value)
{
	struct page *page;
	void *sa = NULL;

	if (unlikely(!kdp_enabled)) {
		*addr = value;
		return;
	}

#if 1
	if (likely((unsigned long)addr > PAGE_OFFSET &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr);
		if (page->kdp_shadow)
			sa = addr;
	}
#else
	if (likely((unsigned long)addr > SOBJ_START &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr - SZ_2G);
		if (page->kdp_shadow)
			sa = page->kdp_shadow +
				((unsigned long)addr & (PAGE_SIZE - 1));
	}
#endif
	else {
		*addr = value;
		return;
	}

	sa = virt_to_shadow(sa);
	unsigned long pgd = virt_to_phys(shadow_pg_dir);
	unsigned long flags;
	asm volatile(
	"	mrs	x2, daif\n"
	"	msr	daifset, #2\n"
	"	mrs	x3, ttbr0_el1\n"
	"	msr	ttbr0_el1, %2\n"
	"	isb	\n"
	"	strh	%w1, [%0]\n"
	"	dmb	ishst\n"
	"	msr	ttbr0_el1, x3\n"
	"	isb	\n"
	"	msr	daif, x2\n"
	: : "r" ((unsigned long)sa), "r" (value), "r" (pgd)
	: "x2", "x3", "memory");
}

void atomic8_write_shadow(unsigned char *addr, unsigned char value)
{
	struct page *page;
	void *sa = NULL;

	if (unlikely(!kdp_enabled)) {
		*addr = value;
		return;
	}

#if 1
	if (likely((unsigned long)addr > PAGE_OFFSET &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr);
		if (page->kdp_shadow)
			sa = addr;
	}
#else
	if (likely((unsigned long)addr > SOBJ_START &&
	           (unsigned long)addr < KDP_STACK_START)) {
		page = virt_to_page((void *)addr - SZ_2G);
		if (page->kdp_shadow)
			sa = page->kdp_shadow +
				((unsigned long)addr & (PAGE_SIZE - 1));
	}
#endif
	else {
		*addr = value;
		return;
	}

	sa = virt_to_shadow(sa);
	unsigned long pgd = virt_to_phys(shadow_pg_dir);
	unsigned long flags;
	asm volatile(
	"	mrs	x2, daif\n"
	"	msr	daifset, #2\n"
	"	mrs	x3, ttbr0_el1\n"
	"	msr	ttbr0_el1, %2\n"
	"	isb	\n"
	"	strb	%w1, [%0]\n"
	"	dmb	ishst\n"
	"	msr	ttbr0_el1, x3\n"
	"	isb	\n"
	"	msr	daif, x2\n"
	: : "r" ((unsigned long)sa), "r" (value), "r" (pgd)
	: "x2", "x3", "memory");
}
