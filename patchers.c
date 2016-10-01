/*
 * Copyright 2013-2016, iH8sn0w. <iH8sn0w@iH8sn0w.com>
 *
 * This file is part of iBoot32Patcher.
 *
 * iBoot32Patcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * iBoot32Patcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with iBoot32Patcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <include/finders.h>
#include <include/functions.h>
#include <include/patchers.h>
#include <include/iBoot32Patcher.h>

int patch_boot_args(struct iboot_img* iboot_in, const char* boot_args) {
	printf("%s: Entering...\n", __FUNCTION__);

	/* Find the pre-defined boot-args from iBoot "rd=md0 ..." */
	void* default_boot_args_str_loc = memstr(iboot_in->buf, iboot_in->len, DEFAULT_BOOTARGS_STR);
	if(!default_boot_args_str_loc) {
		printf("%s: Unable to find default boot-args string!\n", __FUNCTION__);
		return 0;
	}
	printf("%s: Default boot-args string is at %p\n", __FUNCTION__, (void*) GET_IBOOT_FILE_OFFSET(iboot_in, default_boot_args_str_loc));

	/* Find the boot-args string xref within the kernel load routine. */
	void* default_boot_args_xref = iboot_memmem(iboot_in, default_boot_args_str_loc);
	if(!default_boot_args_xref) {
		printf("%s: Unable to find default boot-args string xref!\n", __FUNCTION__);
		return 0;
	}
	printf("%s: boot-args xref is at %p\n", __FUNCTION__, (void*) GET_IBOOT_FILE_OFFSET(iboot_in, default_boot_args_xref));

	/* If new boot-args length exceeds the pre-defined one in iBoot, we need to point the xref somewhere else... */
	if(strlen(boot_args) > strlen(DEFAULT_BOOTARGS_STR)) {
		printf("%s: Relocating boot-args string...\n", __FUNCTION__);

		/* Find the "Reliance on this cert..." string. */
		char* reliance_cert_str_loc = (char*) memstr(iboot_in->buf, iboot_in->len, RELIANCE_CERT_STR);
		if(!reliance_cert_str_loc) {
			printf("%s: Unable to find \"%s\" string!\n", __FUNCTION__, RELIANCE_CERT_STR);
			return 0;
		}
		printf("%s: \"%s\" string found at %p\n", __FUNCTION__, RELIANCE_CERT_STR, GET_IBOOT_FILE_OFFSET(iboot_in, reliance_cert_str_loc));

		/* Point the boot-args xref to the "Reliance on this cert..." string. */
		printf("%s: Pointing default boot-args xref to %p...\n", __FUNCTION__, GET_IBOOT_ADDR(iboot_in, reliance_cert_str_loc));
		*(uint32_t*)default_boot_args_xref = (uintptr_t) GET_IBOOT_ADDR(iboot_in, reliance_cert_str_loc);

		default_boot_args_str_loc = reliance_cert_str_loc;
	}
	printf("%s: Applying custom boot-args \"%s\"\n", __FUNCTION__, boot_args);
	strcpy(default_boot_args_str_loc, boot_args);

	/* This is where things get tricky... (Might run into issues on older loaders)*/

	/* Patch out the conditional branches... */
	void* _ldr_rd_boot_args = ldr_to(default_boot_args_xref);
	if(!_ldr_rd_boot_args) {
		uintptr_t default_boot_args_str_loc_with_base = (uintptr_t) GET_IBOOT_FILE_OFFSET(iboot_in, default_boot_args_str_loc) + get_iboot_base_address(iboot_in->buf);

		_ldr_rd_boot_args = find_next_LDR_insn_with_value(iboot_in, (uint32_t) default_boot_args_str_loc_with_base);
		if(!_ldr_rd_boot_args) {
			printf("%s: Error locating LDR Rx, =boot_args!\n", __FUNCTION__);
			return 0;
		}
	}

	struct arm32_thumb_LDR* ldr_rd_boot_args = (struct arm32_thumb_LDR*) _ldr_rd_boot_args;
	printf("%s: Found LDR R%d, =boot_args at %p\n", __FUNCTION__, ldr_rd_boot_args->rd, GET_IBOOT_FILE_OFFSET(iboot_in, _ldr_rd_boot_args));

	/* Find next CMP Rd, #0 instruction... */
	void* _cmp_insn = find_next_CMP_insn_with_value(ldr_rd_boot_args, 0x100, 0);
	if(!_cmp_insn) {
		printf("%s: Error locating next CMP instruction!\n", __FUNCTION__);
		return 0;
	}

	struct arm32_thumb* cmp_insn = (struct arm32_thumb*) _cmp_insn;
	void* arm32_thumb_IT_insn = _cmp_insn;

	printf("%s: Found CMP R%d, #%d at %p\n", __FUNCTION__, cmp_insn->rd, cmp_insn->offset, GET_IBOOT_FILE_OFFSET(iboot_in, _cmp_insn));

	/* Find the next IT EQ/IT NE instruction following the CMP Rd, #0 instruction... (kinda hacky) */
	while(*(uint16_t*)arm32_thumb_IT_insn != ARM32_THUMB_IT_EQ && *(uint16_t*)arm32_thumb_IT_insn != ARM32_THUMB_IT_NE) {
		arm32_thumb_IT_insn++;
	}

	printf("%s: Found IT EQ/IT NE at %p\n", __FUNCTION__, GET_IBOOT_FILE_OFFSET(iboot_in, arm32_thumb_IT_insn));

	/* MOV Rd, Rs instruction usually follows right after the IT instruction. */
	struct arm32_thumb_hi_reg_op* mov_insn = (struct arm32_thumb_hi_reg_op*) (arm32_thumb_IT_insn + 2);

	printf("%s: Found MOV R%d, R%d at %p\n", __FUNCTION__, mov_insn->rd, mov_insn->rs, GET_IBOOT_FILE_OFFSET(iboot_in, arm32_thumb_IT_insn + 2));

	/* Find the last LDR Rd which holds the null string pointer... */
	int null_str_reg = (ldr_rd_boot_args->rd == mov_insn->rs) ? mov_insn->rd : mov_insn->rs;

	/* + 0x10: Some iBoots have the null string load after the CMP instruction... */
	void* ldr_null_str = find_last_LDR_rd((uintptr_t) (_cmp_insn + 0x10), 0x200, null_str_reg);
	if(!ldr_null_str) {
		printf("%s: Unable to find LDR R%d, =null_str\n", __FUNCTION__, null_str_reg);
		return 0;
	}

	printf("%s: Found LDR R%d, =null_str at %p\n", __FUNCTION__, null_str_reg, GET_IBOOT_FILE_OFFSET(iboot_in, ldr_null_str));

	/* Calculate the new PC relative load from the default boot args xref to the LDR Rd, =null_string location. */
	uint32_t diff = (uint32_t) (GET_IBOOT_FILE_OFFSET(iboot_in, default_boot_args_xref) - GET_IBOOT_FILE_OFFSET(iboot_in, ldr_null_str));

	/* T1 LDR PC-based instructions use the immediate 8 bits multiplied by 4. */
	struct arm32_thumb_LDR* ldr_rd_null_str = (struct arm32_thumb_LDR*) ldr_null_str;
	printf("%s: Pointing LDR R%d, =null_str to boot-args xref...\n", __FUNCTION__, ldr_rd_null_str->rd);
	ldr_rd_null_str->imm8 = (diff / 0x4);

	printf("%s: Leaving...\n", __FUNCTION__);
	return 1;
}

int patch_cmd_handler(struct iboot_img* iboot_in, const char* cmd_str, uint32_t ptr) {
	printf("%s: Entering...\n", __FUNCTION__);

	size_t cmd_str_len = strlen(cmd_str);
	size_t cmd_bytes_len = cmd_str_len + 2;

	char* cmd_bytes = (char*)malloc(cmd_bytes_len);
	if(!cmd_bytes) {
		printf("%s: Out of memory.\n", __FUNCTION__);
		return 0;
	}

	memset(cmd_bytes, 0, cmd_bytes_len);

	/* Fill the buffer to make the string look like \0<cmd>\0 */
	for(int i = 0; i < cmd_str_len; i++) {
		cmd_bytes[i+1] = cmd_str[i];
	}

	/* Find the cmd handler string... */
	void* cmd_ptr_str_loc = memmem(iboot_in->buf, iboot_in->len, cmd_bytes, cmd_bytes_len);

	free(cmd_bytes);

	if(!cmd_ptr_str_loc) {
		printf("%s: Unable to find the cmd \"%s\".\n", __FUNCTION__, cmd_str);
		return 0;
	}
	/* +1 to bring the found offset to the beginning of the cmd string... \0<cmd>\0 --> <cmd>\0 */
	cmd_ptr_str_loc++;

	printf("%s: Found the cmd string at %p\n", __FUNCTION__, GET_IBOOT_FILE_OFFSET(iboot_in, cmd_ptr_str_loc));

	/* Resolve the cmd table referencing the cmd string... */
	struct iboot32_cmd_t* cmd = (struct iboot32_cmd_t*) iboot_memmem(iboot_in, cmd_ptr_str_loc);
	if(!cmd) {
		printf("%s: Unable to find a ref to \"%p\".\n", __FUNCTION__, GET_IBOOT_FILE_OFFSET(iboot_in, cmd_ptr_str_loc));
		return 0;
	}

	printf("%s: Found the cmd string reference at %p\n", __FUNCTION__, GET_IBOOT_FILE_OFFSET(iboot_in, (void*) cmd));

	printf("%s: Pointing \"%s\" from 0x%08x to 0x%08x...\n", __FUNCTION__, cmd_str, cmd->cmd_ptr, ptr);

	/* Point cmd handler to user-specified pointer... */
	cmd->cmd_ptr = ptr;

	printf("%s: Leaving...\n", __FUNCTION__);

	return 1;
}

int patch_debug_enabled(struct iboot_img* iboot_in) {
	printf("%s: Entering...\n", __FUNCTION__);

	/* Find the BL get_value_for_dtre_var insn... */
	void* get_value_for_dtre_bl = find_dtre_get_value_bl_insn(iboot_in, DEBUG_ENABLED_DTRE_VAR_STR);
	if(!get_value_for_dtre_bl) {
		printf("%s: Unable to find appropriate BL insn.\n", __FUNCTION__);
		return 0;
	}

	printf("%s: Patching BL insn at %p...\n", __FUNCTION__, GET_IBOOT_FILE_OFFSET(iboot_in, get_value_for_dtre_bl));

	/* BL get_dtre_value --> MOVS R0, #1; MOVS R0, #1 */
	*(uint32_t*)get_value_for_dtre_bl = bswap32(0x01200120);

	printf("%s: Leaving...\n", __FUNCTION__);
	return 1;
}

int patch_rsa_check(struct iboot_img* iboot_in) {
	printf("%s: Entering...\n", __FUNCTION__);

	/* Find the BL verify_shsh instruction... */
	void* bl_verify_shsh = find_bl_verify_shsh(iboot_in);
	if(!bl_verify_shsh) {
		printf("%s: Unable to find BL verify_shsh!\n", __FUNCTION__);
		return 0;
	}

	printf("%s: Patching BL verify_shsh at %p...\n", __FUNCTION__, GET_IBOOT_FILE_OFFSET(iboot_in, bl_verify_shsh));

	/* BL verify_shsh --> MOVS R0, #0; STR R0, [R3] */
	*(uint32_t*)bl_verify_shsh = bswap32(0x00201860);

	printf("%s: Leaving...\n", __FUNCTION__);
	return 1;
}
