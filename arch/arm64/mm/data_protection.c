#include <linux/data_protection.h>

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

enum pg_level {
	PG_LEVEL_NONE,
	PG_LEVEL_4K,
	PG_LEVEL_2M,
	PG_LEVEL_1G,
	PG_LEVEL_NUM
};

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

void kdp_protect_page(struct page *p)
{
	int order = compound_order(page);
	unsigned long address, writable_address;
	pte_t *pte;
	unsigned int level;

	BUG_ON(order != 1);

	address = (unsigned long) page_address(&p[1]);
	pte = lookup_address(address, &level);
	BUG_ON(!pte);
	BUG_ON(level != PAGE_LEVEL_4K);

	pte_modify(pte, PAGE_KERNEL_READONLY);
}
