#include <env.h>
#include <pmap.h>
#include <printk.h>
#include <trap.h>

extern void handle_int(void);
extern void handle_tlb(void);
extern void handle_sys(void);
extern void handle_mod(void);
extern void handle_reserved(void);
extern void handle_adel(void);
extern void handle_ades(void);

void (*exception_handlers[32])(void) = {
    [0 ... 31] = handle_reserved,
    [0] = handle_int,
    [2 ... 3] = handle_tlb,
    [4] = handle_adel,
    [5] = handle_ades,
#if !defined(LAB) || LAB >= 4
    [1] = handle_mod,
    [8] = handle_sys,
#endif
};

/* Overview:
 *   The fallback handler when an unknown exception code is encountered.
 *   'genex.S' wraps this function in 'handle_reserved'.
 */
void do_reserved(struct Trapframe *tf) {
	print_tf(tf);
	panic("Unknown ExcCode %2d", (tf->cp0_cause >> 2) & 0x1f);
}

void do_adel(struct Trapframe *tf) {
 	// 在此实现相应操作以使修改后指令符合要求
	int* addr = (int*)tf->cp0_epc;
//	printk("0x%x\n",addr);
//	printk("0x%x\n",*addr);
//	printk("0x%x\n",&(*addr));
	//struct Page* page = page_lookup(curenv->env_pgdir, addr, NULL);
	//addr = (int*)(page2kva(page));
	//printk("0x%x\n",addr);
	//printk("0x%x\n",*addr);
	int gpr = get_gpr(addr, tf);
	int imm = get_imm(addr, tf);
	int sum = gpr + imm;
	int offset = sum & 0x3;
	int fix = imm - offset;
	//printk("fix = 0x%x\n",fix&0x0000ffff);
	Pte * pte = 0;
	addr = (int *)(page2kva(page_lookup(curenv->env_pgdir, tf->cp0_epc, &pte)));
	addr = KADDR(PTE_ADDR(*pte)) | (tf->cp0_epc & 0xfff);
	
//	printk("0x%x\n",addr);
//	printk("0x%x\n",*addr);
	*addr = *addr & 0xffff0000;
	*addr = *addr | (fix & 0x0000ffff);
	printk("AdEL handled, new imm is : %04x\n", *addr & 0xffff); // 这里的 new_inst 替换为修改后的指令
}

void do_ades(struct Trapframe *tf) {
 	// 在此实现相应操作以使修改后指令符合要求
	int* addr = (int*)tf->cp0_epc;
	//printk("0x%x\n",addr);
	//struct Page* page = page_lookup(curenv->env_pgdir, addr, NULL);
        //addr = (int*)(page2kva(page));
	//printk("0x%x\n",addr);
	//printk("0x%x\n",*addr);
        int gpr = get_gpr(addr, tf);
        int imm = get_imm(addr, tf);
        int sum = gpr + imm;
        int offset = sum & 0x3;
        int fix = imm - offset;
	Pte*pte = 0;
	addr = (int *)(page2kva(page_lookup(curenv->env_pgdir, tf->cp0_epc, &pte)));
	addr = KADDR(PTE_ADDR(*pte)) | (tf->cp0_epc & 0xfff);	
	
        *addr = *addr & 0xffff0000;
        *addr = *addr | (fix & 0x0000ffff);
	printk("AdES handled, new imm is : %04x\n", *addr & 0xffff); // 这里的 new_inst 替换为修改后的指令
}


int * getkva(int* addr) {
	struct Page* page = page_lookup(curenv->env_pgdir, addr, NULL);
	return (int*)(page2kva(page));
}

int get_gpr(int* addr, struct Trapframe *tf) {
	int cmd = *addr;
	int base = (cmd >> 21);
	base = base & 0x1f;
	return tf->regs[base];
}

int get_imm(int* addr, struct Trapframe *tf) {
	int cmd = *addr;
	int imm = cmd & 0xffff;
	if (((imm >> 15) & 1) == 0) {
		return imm;
	} else {
		return (imm | 0xffff0000);
	}
}
