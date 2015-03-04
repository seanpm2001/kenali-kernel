#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/data_protection.h>

#include <asm/pgtable.h>
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

static void __init map_shadow(void)
{
	struct memblock_region *reg;
	phys_addr_t phys, size = 0;
	unsigned long shadow, addr, length, end, pgd_next, pmd_next;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t *next_reserved_pmd = (pmd_t*)((unsigned long)shadow_pg_dir + PAGE_SIZE);
	pmdval_t prot_sect_shadow;
		
	prot_sect_shadow = PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_NG | PMD_ATTRINDX(MT_NORMAL);
	prot_sect_shadow |= PMD_SECT_PXN | PMD_SECT_UXN;
#ifdef CONFIG_SMP
	prot_sect_shadow |= PMD_SECT_S;
#endif

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

		} while (pgd++, addr = pgd_next, addr != end);
	}

	/* enable shadow page table */
	cpu_do_switch_mm_with_asid(virt_to_phys(shadow_pg_dir), 0);
}

void __init kdp_init(void)
{
	map_shadow();
}

static pte_t *lookup_address(unsigned long address, unsigned int *level)
{
	pgd_t *pgd = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;

	*level = PG_LEVEL_NONE;

	pgd = pgd_offset_k(address);
	if (pgd_none(*pgd))
		return NULL;

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || !pud_present(*pud))
		return NULL;

	*level = PG_LEVEL_1G;
	/* This should never happen */
	if (pud_bad(*pud))
		return (pte_t *)pud;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || !pmd_present(*pmd))
		return NULL;

	*level = PG_LEVEL_2M;
	/* This should never happen */
	if (pmd_bad(*pmd))
		return (pte_t *)pmd;

	*level = PG_LEVEL_4K;

	pte = pte_offset_kernel(pmd, address);
	if (!pte_present(*pte))
		return NULL;

	return pte;
}

void kdp_protect_page(struct page *page)
{
	int order;
	unsigned long address;
	pte_t *ppte, pte;
	unsigned int level;

	order = compound_order(page);
	BUG_ON(order != 1);

	address = (unsigned long)page_address(&page[1]);
	ppte = lookup_address(address, &level);
	BUG_ON(!ppte);
	BUG_ON(level != PG_LEVEL_4K);

	pte = pte_modify(*ppte, PAGE_KERNEL_READONLY);
}
