#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/data_protection.h>

#include <asm/sections.h>
#include <asm/pgtable.h>
#include <asm/proc-fns.h>
#include <asm/tlbflush.h>

int kdp_enabled;

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

		pr_info("KCFI: maping shadow address 0x%016lx - 0x%016lx\n", addr, end);
		do {
			pgd_next = pgd_addr_end(addr, end);
			pud = pud_offset(pgd, addr);
			if (pud_none(*pud)) {
				pmd = next_reserved_pmd;
				pr_info("KCFI: alloc reserved pmd = 0x%016llx\n", __pa(pmd));
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
	ro_end = (unsigned long)__init_begin;

	pr_info("KCFI: mark kernel code section (0x%16lx - 0x%016lx) as RX\n",
			code_start, code_end);
	pr_info("KCFI: mark kernel rodata section (0x%16lx - 0x%016lx) as RO\n",
			ro_start, ro_end);

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
	if (unlikely(!pte_present(*pte)))
		return NULL;

	return pte;
}

static void inline flush_kern_tlb_one_page(void* address)
{
	asm volatile(
	"	dsb	ishst\n"
	"	lsr	%0, %0, #12\n"
	"	tlbi	vaale1is, %0\n"
	"	dsb	ish\n"
	"	isb"
	: : "r" (address) : "memory");
}

void kdp_protect_one_page(void* address)
{
	pte_t *ptep, pte;
	unsigned int level;

	if (unlikely(address == NULL))
		return;

	//if (kdp_enabled)
	//	pr_info("KCFI: protect page %p\n", address);

	ptep = lookup_address((unsigned long)address, &level);
	BUG_ON(!ptep);
	BUG_ON(level != PG_LEVEL_4K);

	pte = pte_modify(*ptep, PAGE_KERNEL_READONLY);
	if (likely(kdp_enabled)) {
		set_pte(ptep, pte);
		flush_kern_tlb_one_page(address);
	} else {
		set_pte(virt_to_shadow(ptep), pte);
	}
}

void kdp_unprotect_one_page(void* address)
{
	pte_t *ptep, pte;
	unsigned int level;

	if (unlikely(address == NULL))
		return;

	//if (kdp_enabled)
	//	pr_info("KCFI: unprotect page %p\n", address);

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

void kdp_enable(void)
{
	pgd_t* old_pg = cpu_get_pgd();
	pr_info("KCFI: old pgd = 0x%p, zero page = 0x%lx\n",
		old_pg, empty_zero_page);

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

	/* restore old pgd */
	cpu_switch_mm_with_asid(old_pg, 0);
	flush_tlb_all();

	/* set data protection as enabled */
	kdp_enabled = 1;
}

void kdp_protect_page(struct page *page)
{
	int order;
	void *address;

	if (page == NULL)
		return;

	order = compound_order(page);
	BUG_ON(order != 1);

	address = page_address(&page[1]);
	kdp_protect_one_page(address);
}

