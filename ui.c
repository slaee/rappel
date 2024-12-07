#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <histedit.h>

// #include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "assemble.h"
#include "common.h"
#include "arch.h"
#include "display.h"
#include "exedir.h"
#include "elf_gen.h"
#include "ptrace.h"
#include "ptrace_arch.h"

#include "ui.h"

extern struct options_t options;
extern int exiting;

static int in_block;

static unsigned long current_address;

size_t 
get_instruction_length(const char *assembly_code) {
    ks_engine *ks;
    unsigned char *encode;
    size_t size, count;
    size_t length = 0;

    // Initialize Keystone for x86 (32-bit)
    if (ks_open(KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK) {
        fprintf(stderr, "Keystone initialization failed!\n");
        exit(EXIT_FAILURE);
    }

    // Assemble the provided assembly code
    if (ks_asm(ks, assembly_code, 0, &encode, &size, &count) != KS_ERR_OK) {
        fprintf(stderr, "Keystone assembly failed: %s\n", ks_strerror(ks_errno(ks)));
        ks_close(ks);
        return 0;
    }

    // Instruction length is the size of the generated machine code
    length = size;

    // Free resources
    ks_free(encode);
    ks_close(ks);

    return length;
}

// size_t 
// get_instruction_length(const unsigned char *buf, size_t size) {
//     csh handle;
//     cs_insn *insn;
//     size_t len = 0;

//     // Initialize Capstone disassembler for x86 (32-bit)
//     if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
//         fprintf(stderr, "Capstone initialization failed!\n");
//         exit(EXIT_FAILURE);
//     }

//     // Disassemble the instruction(s)
//     size_t count = cs_disasm(handle, buf, size, 0x0, 1, &insn);
//     if (count > 0) {
//         // The length of the first instruction (in bytes)
//         len = insn[0].size;
//         cs_free(insn, count);
//     } else {
//         fprintf(stderr, "Failed to disassemble instruction\n");
//     }

//     cs_close(&handle);
//     return len;
// }

static
char const* _prompt(
		EditLine *const e)
{
    static char prompt[64];  // Buffer to hold the prompt string

    if (in_block) {
        snprintf(prompt, sizeof(prompt), "...: ", current_address); // Use current_address for address
    } else {
        snprintf(prompt, sizeof(prompt), "0x%lx: ", current_address);
    }

    return prompt;
}

#ifdef ARCH_64BIT  // 64-bit architecture
    #define GET_IP(info)  (info.regs_struct.rip)
#else  // 32-bit architecture
    #define GET_IP(info)  (info.regs_struct.eip)
#endif

static
void _help(void)
{
	printf("Commands:\n");
	printf(".quit                    - quit\n");
	printf(".help                    - display this help\n");
	printf(".info                    - display registers\n");
	printf(".begin                   - start a block, input will not be assembled/run until '.end'\n");
	printf(".end                     - assemble and run the prior block\n");
	printf(".showmap                 - shortcut for cat /proc/<pid>/maps\n");
	printf(".allregs <on|off>        - toggle all register display\n");
	printf(".read <address> [amount] - read <amount> bytes of data from address using ptrace [16]\n");
	printf(".write <address> <data>  - write data starting at address using ptrace\n");
	printf(".reset                   - resets rappel\n");
}

static
void _ui_read(
		const pid_t child_pid,
		const char *line)
{
	char *dupline = strdup(line);

	if (!dupline) {
		perror("strdup");
		return;
	}

	char *saveptr;

	const char *dotread = strtok_r(dupline, " ", &saveptr);

	if (!dotread || strcasecmp(dotread, ".read"))
		goto bail;

	const char *addr_str = strtok_r(NULL, " ", &saveptr);

	if (!addr_str)
		goto bail;

	errno = 0;
	const unsigned long addr = strtoul(addr_str, NULL, 0x10);

	if (addr == ULONG_MAX && errno) {
		perror("strtoul");
		goto bail;
	}

	const char *sz_str = strtok_r(NULL, " ", &saveptr);

	unsigned long sz = 0x10;

	if (sz_str && strlen(sz_str)) {
		errno = 0;
		sz = strtoul(sz_str, NULL, 0);

		if (sz == ULONG_MAX && errno) {
			perror("strtoul");
			goto bail;
		}
	}

	uint8_t *buf = xmalloc(sz);

	if (!ptrace_read(child_pid, (void *)addr, buf, sz))
		dump(buf, sz, addr);

	free(buf);

bail:
	free(dupline);
}

static
void _ui_write(
		const pid_t child_pid,
		const char *line)
{
	char *dupline = strdup(line);

	if (!dupline) {
		perror("strdup");
		return;
	}

	char *saveptr;

	const char *dotread = strtok_r(dupline, " ", &saveptr);

	if (!dotread || strcasecmp(dotread, ".write"))
		goto bail;

	const char *addr_str = strtok_r(NULL, " ", &saveptr);

	if (!addr_str)
		goto bail;

	errno = 0;
	const unsigned long addr = strtoul(addr_str, NULL, 0x10);

	if (addr == ULONG_MAX && errno) {
		perror("strtoul");
		goto bail;
	}

	const char *val_str = strtok_r(NULL, " ", &saveptr);

	if (!val_str) goto bail;

	char *p = strchr(val_str, '\n');
	if (p) *p = 0;

	const size_t val_len = strlen(val_str);

	if (val_len % 2) {
		printf("Memory write values should be hex encoded, even length strings\n");
		goto bail;
	}

	const size_t sz = val_len / 2;

	uint8_t *buf = xmalloc(sz);
	memset(buf, 0, sz);

	for (size_t ii = 0; ii < val_len; ii += 2) {
		uint8_t a = hex_hashmap[(uint8_t)val_str[ii + 0]];
		uint8_t b = hex_hashmap[(uint8_t)val_str[ii + 1]];

		if (a == 0xff || b == 0xff) {
			printf("Memory write values should be hex encoded, even length strings\n");
		}

		buf[ii / 2] = a << 4 | b;
	}

	ptrace_write(child_pid, (void *)addr, buf, sz);

	free(buf);

bail:
	free(dupline);
}

static const
pid_t _gen_child(void) {
	uint8_t buf[PAGE_SIZE];
	mem_assign(buf, PAGE_SIZE, TRAP, TRAP_SZ);

	uint8_t *elf;
	const size_t elf_sz = gen_elf(&elf, options.start, (uint8_t *)buf, PAGE_SIZE);

	const int exe_fd = write_exe(elf, elf_sz, options.savefile);

	free(elf);

	const pid_t tracee = fork();

	if (tracee < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	} else if (tracee == 0) {
		ptrace_child(exe_fd);
		abort();
	}

	// Parent
	close(exe_fd);

	return tracee;
}

void interact(
		const char *const argv_0)
{
	EditLine *const el = el_init(argv_0, stdin, stdout, stderr);
	el_set(el, EL_PROMPT, &_prompt);
	el_set(el, EL_EDITOR, "emacs");

	History *const hist = history_init();
	if (!hist) {
		fprintf(stderr, "Could not initalize history\n");
		exit(EXIT_FAILURE);
	}

	HistEvent ev;
	history(hist, &ev, H_SETSIZE, 100);

	char hist_path[PATH_MAX] = { 0 };
	int ret = snprintf(hist_path, sizeof(hist_path), "%s/history", options.rappel_dir);
	if (ret < 0) {
		fprintf(stderr, "Path exceeds max path length: %s/history", options.rappel_dir);
		exit(EXIT_FAILURE);
	}

	history(hist, &ev, H_LOAD, hist_path);

	el_set(el, EL_HIST, history, hist);

	pid_t child_pid = _gen_child();

	verbose_printf("child process is %d\n", child_pid);

	if (options.verbose) _help();

	char buf[PAGE_SIZE] = { 0 };
	size_t buf_sz = 0;
	int end = 0, child_died = 0;

	struct proc_info_t info = { 0 };
	ARCH_INIT_PROC_INFO(info);

	ptrace_launch(child_pid);
	ptrace_cont(child_pid, &info);

	current_address = options.start;

	ptrace_reap(child_pid, &info);

	display(&info);

	for (;;) {
		int count;
		const char *const line = el_gets(el, &count);

		if (count == -1) {
			perror("el_gets");
			exit(EXIT_FAILURE);
		}

		// count is 0 == ^d
		if (!count || strcasestr(line, ".quit") || strcasestr(line, ".exit")) break;

		// We have input, add it to our history
		history(hist, &ev, H_ENTER, line);

		// If we start with a ., we have a command
		if (line[0] == '.') {
			if (strcasestr(line, "help")) {
				_help();
				continue;
			}

			if (strcasestr(line, "info")) {
				display(&info);
				continue;
			}

			if (strcasestr(line, "showmap")) {
				char cmd[PATH_MAX] = { 0 };
				snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", child_pid);

				if (system(cmd))
					fprintf(stderr, "sh: %s failed\n", cmd);

				continue;
			}


			if (strcasestr(line, "read")) {
				_ui_read(child_pid, line);
				continue;
			}

			if (strcasestr(line, "write")) {
				_ui_write(child_pid, line);
				continue;
			}

			if (strcasestr(line, "allregs")) {
				if (strcasestr(line, "on"))
					options.allregs = 1;
				if (strcasestr(line, "off"))
					options.allregs = 0;
				continue;
			}

			if (strcasestr(line, "begin")) {
				in_block = 1;
				continue;
			}

			// Note the lack of continue. Need to fall through...
			if (strcasestr(line, "end")) {
				in_block = 0;
				end = 1;
			}

			if (strcasestr(line, "reset")) {
				printf("Resetting child process...\n");

				if (!child_died) {
					ptrace_detatch(child_pid, &info);
				}

				// Clear state
				memset(buf, 0, sizeof(buf));
				buf_sz = 0;
				end = 0;
				in_block = 0;
				current_address = options.start;

				// Clear history
				history(hist, &ev, H_CLEAR);

				// Create a new child process
				child_pid = _gen_child();

				// Relaunch the child process
				ARCH_INIT_PROC_INFO(info);
				ptrace_launch(child_pid);
				ptrace_cont(child_pid, &info);				
				ptrace_reap(child_pid, &info);
				display(&info);

				continue;
			}
		}

		if (buf_sz + count > sizeof(buf)) {
			printf("Buffer full (max: 0x%zx), please use '.end'\n", sizeof(buf));
			continue;
		}

		// Since we fell through, we want to avoid adding .end to our buffer
		if (!end) {
			memcpy(buf + buf_sz, line, count);
			buf_sz += count;
		}

		if (!in_block) {
			verbose_printf("Trying to assemble (%zu):\n%s", buf_sz, buf);

			uint8_t bytecode[PAGE_SIZE];
			const size_t bytecode_sz = assemble(bytecode, sizeof(bytecode), buf, buf_sz);

			verbose_printf("Got asm (%zu):\n", bytecode_sz);
			verbose_dump(bytecode, bytecode_sz, -1);

			if (!bytecode_sz) {
				fprintf(stderr, "assembled to 0 length bytecode:\n%s", buf);
			}

			memset(buf, 0, sizeof(buf));
			buf_sz = 0;
			end    = 0;

			if (!bytecode_sz) {
				continue;
			}

			// round up to nearest ptr_sz + size of at least one trap
			const size_t code_buf_sz = ROUNDUP(bytecode_sz + TRAP_SZ, sizeof(long));
			uint8_t *code_buf = xmalloc(code_buf_sz);
			mem_assign((uint8_t *)code_buf, code_buf_sz, TRAP, TRAP_SZ);
			memcpy(code_buf, bytecode, bytecode_sz);

			ptrace_write(child_pid, (void *)options.start, code_buf, code_buf_sz);

			ptrace_reset(child_pid, options.start);
			ptrace_cont(child_pid, &info);

			if (ptrace_reap(child_pid, &info)) {
				child_died = 1;
				break;
			}
			display(&info);

			// Calculate instruction length using Capstone
			size_t instr_len = get_instruction_length(code_buf);

			// Update current_address
			current_address += instr_len;
			free(code_buf);
		}
	}

	if (!child_died)
		ptrace_detatch(child_pid, &info);

	printf("\n");

	// we close this one with a file pointer so we can truncate the file
	FILE *hist_save = fopen(hist_path, "wb");
	REQUIRE (hist_save != NULL);

	history(hist, &ev, H_SAVE_FP, hist_save);

	REQUIRE (fclose(hist_save) == 0);

	history_end(hist);
	el_end(el);
}
