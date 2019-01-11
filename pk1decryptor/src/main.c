/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#include "utils.h"
#include "exception_handlers.h"
#include "panic.h"
#include "hwinit.h"
#include "di.h"
#include "timers.h"
#include "fs_utils.h"
#include "stage2.h"
#include "chainloader.h"
#include "cluster.h"
#include "car.h"
#include "mc.h"
#include "tsec.h"
#include "sdmmc/sdmmc.h"
#include "lib/fatfs/ff.h"
#include "lib/log.h"
#include "lib/vsprintf.h"
#include "lib/ini.h"
#include "display/video_fb.h"

extern void (*__program_exit_callback)(int rc);

static void *g_framebuffer;

#define CONFIG_LOG_LEVEL_KEY "log_level"

char* PATH[4] = {"pk1decryptor/package1", "pk1decryptor/package1_dev", "pk1decryptor/package1_nodec", "pk1decryptor/package1_dev_nodec"};

static void setup_env(void) {
    g_framebuffer = (void *)0xC0000000;

    /* Initialize hardware. */
    nx_hwinit();

    /* Check for panics. */
    check_and_display_panic();

    /* Zero-fill the framebuffer and register it as printk provider. */
    video_init(g_framebuffer);

    /* Initialize the display. */
    display_init();

    /* Set the framebuffer. */
    display_init_framebuffer(g_framebuffer);

    /* Turn on the backlight after initializing the lfb */
    /* to avoid flickering. */
    display_backlight(true);

    /* Set up the exception handlers. */
    setup_exception_handlers();
    
    /* Mount the SD card. */
    mount_sd();
}

static void cleanup_env(void) {
    /* Unmount the SD card. */
    unmount_sd();

    display_backlight(false);
    display_end();
}

static void exit_callback(int rc) {
    (void)rc;
    relocate_and_chainload();
}

//Aligned memcpy to read MMIO correctly
void safe_memcpy(void* dst, void* src, uint32_t sz) {
	for (size_t i = 0; i < (sz/4); i++) { ((volatile uint32_t *)dst)[i] = ((volatile uint32_t *)src)[i]; }
}

void map_page(uint32_t va, uint32_t pa, uint32_t read, uint32_t write, uint32_t nonsecure) {
	static uint32_t counter = 0;
	
	//Check and setup args
	if(((va & 0xFFF) != 0) || ((pa & 0xFFF) != 0)) {
		return;
	}
	read = !(!read);
	write = !(!write);
	nonsecure = !(!nonsecure);
	
	//Get address of page table, and create PDE if necessary
	volatile uint32_t *page_directory = (volatile uint32_t*)0x81000000;
	volatile uint32_t *page_table = (volatile uint32_t*)0;
	uint32_t pde = page_directory[(va >> 22)];
	if(pde == 0) {
		counter++;
		page_table = (volatile uint32_t*)(0x81000000 + counter*0x1000);
		memset((void*)page_table, 0, 0x1000);
		page_directory[(va >> 22)] = (1 << 31) | (1 << 30) | (1 << 29) | (1 << 28) | ((uint32_t)page_table >> 12);
	}
	else {
		page_table = (volatile uint32_t*)(pde << 12);
	}
	
	//Setup page in page table
	page_table[((va & 0x003FF000) >> 12)] = (read << 31) | (write << 30) | (nonsecure << 29) | (pa >> 12);
}

void map_page_range(uint32_t va, uint32_t pa, uint32_t num, uint32_t read, uint32_t write, uint32_t nonsecure) {
	for(uint32_t i = 0; i < num; i++) {
		map_page(va + i*0x1000, pa + i*0x1000, read, write, nonsecure);
	}
}

void setup_page_table() {
	memset((void*)0x81000000, 0, 0x1000);
	map_page(0x60006000, 0x82000000, 1, 1, 1);
	map_page(0x7000f000, 0x82001000, 1, 0, 1);
	map_page(0x7000e000, 0x82002000, 1, 0, 1);
	map_page(0x60007000, 0x82003000, 0, 1, 1);
	map_page(0x70012000, 0x82004000, 1, 1, 1);
	map_page(0x70019000, 0x82005000, 1, 0, 1);
	map_page_range(0x40016000, 0x83016000, 41, 1, 1, 1);
	map_page(0x6000F000, 0x82007000, 1, 1, 1);
}

//Writes 1 to 0x70019010, reads back and write the result to 0x40003F80. Then infloops.
uint32_t aarch64_payload[12] = {0x52800020, 0x580000E2, 0x58000103, 0xB9000040, 0xB9400041, 0xB9000061, 0x14000000, 0x00000000, 0x70019010, 0x00000000, 0x40003F80, 0x00000000};

void enable_SMMU() {
	//Disable the aperture since it has precedence over the SMMU
	mc_disable_ahb_redirect();
	
	setup_page_table();
	
	//Set the page table base for ASID 0
	volatile uint32_t *smmu_ptb_asid = (volatile uint32_t *)(0x70019000 + 0x1C);
	volatile uint32_t *smmu_ptb_data = (volatile uint32_t *)(0x70019000 + 0x20);
	*smmu_ptb_asid = 0;
	*smmu_ptb_data = (1 << 31) | (1 << 30) | (1 << 29) | (0x81000000 >> 12);
	
	//Set ASID 1 as invalid
	*smmu_ptb_asid = 1;
	*smmu_ptb_data = 0;
	
	//Set ASIDs and enable translation for TSEC
	volatile uint32_t *smmu_tsec_asid = (volatile uint32_t *)(0x70019000 + 0x294);
	*smmu_tsec_asid = (1 << 31) | (1 << 24) | (1 << 16) | (1 << 8) | 0;
	
	//Flush caches
	volatile uint32_t *smmu_tlb_flush = (volatile uint32_t *)(0x70019000 + 0x30);
	volatile uint32_t *smmu_ptc_flush = (volatile uint32_t *)(0x70019000 + 0x34);
	*smmu_tlb_flush = 0;
	*smmu_ptc_flush = 0;
	
	//Power on the CCPLEX to enable the SMMU globally (requires a secure write)
	volatile uint32_t *test = (volatile uint32_t *)(0x40003F80);
	memcpy((void*)0x40003F00, aarch64_payload, 12*4);
	/*for(int i = 0; i < 0x700; i++) {
		*test = *(volatile uint32_t*)(0x80000000+i*0x100000);
	}*/
	*test = 0xFF;
	cluster_boot_cpu0(0x40003F00);
	mdelay(500);
	if(*test != 1) {
		fatal_error("Failed to enable SMMU!\n");
	}
}

static int tsec_dma_wait_idle()
{
    volatile tegra_tsec_t *tsec = tsec_get_regs();    
    uint32_t timeout = (get_time_ms() + 10000);

    while (!(tsec->FALCON_DMATRFCMD & 2))
        if (get_time_ms() > timeout)
            return 0;

    return 1;
}

static int tsec_dma_phys_to_flcn(bool is_imem, uint32_t flcn_offset, uint32_t phys_offset)
{
    volatile tegra_tsec_t *tsec = tsec_get_regs(); 
    uint32_t cmd = 0;

    if (!is_imem)
        cmd = 0x600;
    else
        cmd = 0x10;

    tsec->FALCON_DMATRFMOFFS = flcn_offset;
    tsec->FALCON_DMATRFFBOFFS = phys_offset;
    tsec->FALCON_DMATRFCMD = cmd;

    return tsec_dma_wait_idle();
}

int load_TSEC_FW(void* tsec_fw) {
	volatile tegra_tsec_t *tsec = tsec_get_regs();

    /* Enable clocks. */
    clkrst_reboot(CARDEVICE_HOST1X);
    clkrst_reboot(CARDEVICE_TSEC);
    clkrst_reboot(CARDEVICE_SOR_SAFE);
    clkrst_reboot(CARDEVICE_SOR0);
    clkrst_reboot(CARDEVICE_SOR1);
    clkrst_reboot(CARDEVICE_KFUSE);

    /* Configure Falcon. */
    tsec->FALCON_DMACTL = 0;
    tsec->FALCON_IRQMSET = 0xFFF2;
    tsec->FALCON_IRQDEST = 0xFFF0;
    tsec->FALCON_ITFEN = 3;
    
    if (!tsec_dma_wait_idle())
    {
        /* Disable clocks. */
        clkrst_disable(CARDEVICE_KFUSE);
        clkrst_disable(CARDEVICE_SOR1);
        clkrst_disable(CARDEVICE_SOR0);
        clkrst_disable(CARDEVICE_SOR_SAFE);
        clkrst_disable(CARDEVICE_TSEC);
        clkrst_disable(CARDEVICE_HOST1X);
    
        return -1;
    }
    
    /* Load firmware. */
    tsec->FALCON_DMATRFBASE = (uint32_t)tsec_fw >> 8;
    for (uint32_t addr = 0; addr < 0x2900; addr += 0x100)
    {
        if (!tsec_dma_phys_to_flcn(true, addr, addr))
        {
            /* Disable clocks. */
            clkrst_disable(CARDEVICE_KFUSE);
            clkrst_disable(CARDEVICE_SOR1);
            clkrst_disable(CARDEVICE_SOR0);
            clkrst_disable(CARDEVICE_SOR_SAFE);
            clkrst_disable(CARDEVICE_TSEC);
            clkrst_disable(CARDEVICE_HOST1X);
        
            return -2;
        }
    }
    
    /* Unknown host1x write. */
    MAKE_HOST1X_REG(0x3300) = 0x34C2E1DA;
    
    /* Execute firmware. */
    tsec->FALCON_SCRATCH1 = 0;
    tsec->FALCON_SCRATCH0 = 1;
    tsec->FALCON_BOOTVEC = 0;
	enable_SMMU(); //We enable the SMMU just before the TSEC starts.
    tsec->FALCON_CPUCTL = 2;
    
    if (!tsec_dma_wait_idle())
    {
        /* Disable clocks. */
        clkrst_disable(CARDEVICE_KFUSE);
        clkrst_disable(CARDEVICE_SOR1);
        clkrst_disable(CARDEVICE_SOR0);
        clkrst_disable(CARDEVICE_SOR_SAFE);
        clkrst_disable(CARDEVICE_TSEC);
        clkrst_disable(CARDEVICE_HOST1X);
    
        return -3;
    }

    return 0;
}

int main(void) {
	ScreenLogLevel log_level = SCREEN_LOG_LEVEL_MANDATORY;
	uint8_t mode = 0;
    
    /* Initialize the display, console, etc. */
    setup_env();
    
    /* Override the global logging level. */
    log_set_log_level(log_level);
	
	//Get the mode from package1's name
	if(get_file_size(PATH[3]) > 0) {mode = 3;}
	else if(get_file_size(PATH[2]) > 0) {mode = 2;}
	else if(get_file_size(PATH[1]) > 0) {mode = 1;}
	
	//Setup the fake MMIO region
	memset((void*)0x82000000, 0, 0x8000); //DRAM can have things in it so clean the region
	safe_memcpy((void*)0x82000000, (void*)0x60006000, 0x1000); //Copy CAR
	safe_memcpy((void*)0x82005000, (void*)0x70019000, 0x1000); //Copy MC
	volatile uint32_t *fuse = (volatile uint32_t *)(0x82001800);
	fuse[0x110/4] = 0x83;
	if(mode & 1) {
		fuse[0x1d8/4] = 7;
	}
	else {
		fuse[0x1d8/4] = 0x204;
	}
	volatile uint32_t *car = (volatile uint32_t *)(0x82000000);
	//TSEC wants CLK_RST_CONTROLLER_CLK_SOURCE_TSEC_0 to be equal to 2
	car[0x1f4/4] = 2;
	//And obviously it wants the aperture fully open
	volatile uint32_t *mc = (volatile uint32_t *)(0x82005000);
	mc[0x65C/4] = 0;
	mc[0x660/4] = 0x80000000;
	
	//Setup the fake IRAM region and load the right package1
	memset((void*)0x83000000, 0, 0x40000); //DRAM can have things in it so clean the region
	uint32_t pk1_size = get_file_size(PATH[mode]);
	if(!pk1_size || pk1_size > 0x30000 || read_from_file((void*)0x83010000, pk1_size, PATH[mode]) != pk1_size) {
		fatal_error("The program couldn't read package1!\nPlease put a valid package1 in the pk1decryptor folder.");
	}
	
	//The big deal
	if(load_TSEC_FW((void*)(0x83010000+0xE00))) {
		fatal_error("The TSEC FW wasn't loaded correctly!");
	}
	
	//Let's get the keys written to the security engine
	volatile tegra_tsec_t *tsec = tsec_get_regs();
	volatile uint32_t *key_data = (volatile uint32_t *)(0x82004000 + 0x320);
	volatile uint32_t *key_buf = (volatile uint32_t *)(0x82006000);
	uint32_t old_key_data = *key_data;
	uint32_t buf_counter = 0;
	while(tsec->FALCON_CPUCTL < 8) {
		if(*key_data != old_key_data) {
			old_key_data = *key_data;
			key_buf[buf_counter] = *key_data;
			buf_counter++;
		}
	}
	
	//If the reset vector was written then the TSEC wrote the keys and decrypted Package1
	volatile uint32_t *check = (volatile uint32_t *)(0x82007200);
	if(mode & 2) {
		check = (volatile uint32_t *)(0x82006000);
	}
	if(!*check) {
		fatal_error("The TSEC FW was incorrect or wasn't satisfied!");
	}
	
	safe_memcpy((void*)0x82006FF0, (void*)0x7000F9A4, 0x10); //Little bonus: the SBK
	
	//We write everything to SD
	mc_enable_ahb_redirect();
	if(!(mode & 2))
		write_to_file((void*)0x83010000, pk1_size, "pk1decryptor/package1_dec");
	write_to_file((void*)0x82006000, 0x10, "pk1decryptor/key_0xC");
	write_to_file((void*)0x82006010, 0x10, "pk1decryptor/key_0xD");
	write_to_file((void*)0x82006FF0, 0x10, "pk1decryptor/key_0xE");
	
	print(SCREEN_LOG_LEVEL_MANDATORY, "Success!\n");
	if(mode & 2) {
		print(SCREEN_LOG_LEVEL_MANDATORY, "The TSEC device key, the TSEC root key and the SBK were all saved to the SD card.\n");
	}
	else {
		print(SCREEN_LOG_LEVEL_MANDATORY, "Reset vector: 0x%08x\n", *check);
		print(SCREEN_LOG_LEVEL_MANDATORY, "The decrypted Package1, the TSEC device key, the TSEC root key and the SBK\nwere all saved to the SD card.\n");
	}
	print(SCREEN_LOG_LEVEL_MANDATORY, "Press POWER to reboot.\n");
	
	wait_for_button_and_reboot();
    
    /* Deinitialize the display, console, etc. */
    cleanup_env();

    /* Finally, after the cleanup routines (__libc_fini_array, etc.) are called, jump to Stage2. */
    __program_exit_callback = exit_callback;
    return 0;
}
