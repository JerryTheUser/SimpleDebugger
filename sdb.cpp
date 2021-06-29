#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <map>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>
#include "elftool.h"

using namespace std;

class SDB{
public:
	// General function call
	using func_ptr = void (SDB::*)(vector<string>);
	
	// Program state type
	enum class state {ANY, LOADED, RUNNING};
	
	// Break point type
	typedef struct bp_t {
		long long addr;
		unsigned char orig_byte;
	} bp_t;

private:
	state current;
	vector<bp_t> breakpoints;
	int bp_idx;
	static map<string, func_ptr> func_map;
	static map<string, size_t> reg_map;
	static map<state, string> state_map;

	string program;
    pid_t cpid;
	
	elf_handle_t *eh;
    elf_strtab_t *tab;
	int text_idx;
	long long base_addr = -1;
	long long last_addr = -1;
	long long last_disasm = -1;
	long long last_dump = -1;

	csh capstone_handler;
	struct user_regs_struct regs;
	vector<string> split(string);
	void program_termination(int);
	void get_base_address();
	void get_maps();
	void exec_impl(vector<string>, bool);
	void continue_impl(vector<string>, __ptrace_request);
	void check_bp();
	void print_ins(cs_insn);

public:
    SDB() {
    	init();
    };

    SDB(string program) {
		init();
		load_program({"", program});
    }; 
	   
    ~SDB() {
		elf_close(eh);
		cs_close(&capstone_handler);
	};

	void run();

private:
    void init();
	void load_program(vector<string>);
	void start_exec(vector<string>);
	void exec(vector<string>);
	void set_bp(vector<string>);
	void del_bp(vector<string>);
	void list_bp(vector<string>);
	void continue_exec(vector<string>);
	void dis_asm(vector<string>);
	void dump_mem(vector<string>);
	void quit(vector<string>);
	void get_reg(vector<string>);
	void get_all_reg(vector<string>);
	void set_reg(vector<string>);
	void print_mem_layout(vector<string>);
	void print_help(vector<string>);
	void run_a_instruction(vector<string>);
};

vector<string> SDB::split(string str){
	vector<string> ret;
	for(size_t pos = str.find(' ') ; pos != string::npos ; pos = str.find(' ')){
		ret.emplace_back(str.substr(0, pos));
		while(str[pos+1] == ' ') ++pos;
		str = str.substr(pos+1);
	}
	ret.emplace_back(str);
	return ret;
}

void SDB::program_termination(int status){
	if (WIFEXITED(status))
		cerr << dec << "** Child process " << cpid << " terminated normally (code " << WEXITSTATUS(status) << ")." << endl;
	else if (WIFSIGNALED(status))
		cerr << dec << "** Child process " << cpid << " killed by signal " << WTERMSIG(status) << "." << endl;
	current = state::LOADED;
	cpid = 0;
	for (auto& item : breakpoints)
		item.addr -= base_addr;
	if (last_disasm != -1)
		last_disasm -= base_addr;
	base_addr = -1;
	last_addr = -1;
	last_dump = -1;
	bp_idx = -1;
}

void SDB::get_base_address(){
	ifstream infile(("/proc/" + to_string(cpid) + "/maps").c_str());
	string line;
	size_t pos;
    vector<string> columns;
	while(getline(infile, line)){
		pos = line.find('-');
		columns = split(line.substr(pos+1));
		char cwd[256];
		getcwd(cwd, sizeof(cwd));
		if (columns[1].substr(0, columns[1].size() - 1) == "r-x" && columns[5] == (string(cwd) + "/" + program))
		{
			base_addr = stoll(line.substr(0, pos), nullptr, 16);
			last_addr = stoll(columns[0], nullptr, 16);
			break;
		}
	}
	infile.close();
	return;
}

void SDB::get_maps(){
	ifstream infile(("/proc/" + to_string(cpid) + "/maps").c_str());
	string line;
	size_t pos, pos2;
    vector<string> columns;
	while(getline(infile, line)){
		pos = line.find('-');
		pos2 = 0;
		columns = split(line.substr(pos+1));
		while (columns[2][pos2] == '0' && pos2 != columns[2].size()-1)
            ++pos2;
		cerr << setfill('0') << hex << right << setw(16) << line.substr(0, pos) << "-"
			<< setw(16) << columns[0] << " " << columns[1].substr(0, columns[1].size()-1) << " "
			<< setfill(' ') << left << setw(8) << columns[2].substr(pos2) << " "
			<< columns[5] << endl;
	}
	infile.close();
	return;
}

map<string, SDB::func_ptr> SDB::func_map = {
	{"h", &SDB::print_help},
	{"help", &SDB::print_help},
	{"load", &SDB::load_program},
	{"run", &SDB::exec},
	{"r", &SDB::exec},
	{"start", &SDB::start_exec},
	{"cont", &SDB::continue_exec},
	{"c", &SDB::continue_exec},
	{"si", &SDB::run_a_instruction},
	{"get", &SDB::get_reg},
	{"g", &SDB::get_reg},
	{"getregs", &SDB::get_all_reg},
	{"set", &SDB::set_reg},
	{"s", &SDB::set_reg},
	{"q", &SDB::quit},
	{"exit", &SDB::quit},
	{"list", &SDB::list_bp},
	{"l", &SDB::list_bp},
	{"break", &SDB::set_bp},
	{"b", &SDB::set_bp},
	{"delete", &SDB::del_bp},
	{"vmmap", &SDB::print_mem_layout},
	{"m", &SDB::print_mem_layout},
	{"disasm", &SDB::dis_asm},
	{"d", &SDB::dis_asm},
	{"dump", &SDB::dump_mem},
	{"x", &SDB::dump_mem}
};

map<string, size_t> SDB::reg_map = {
	{"r15", 0},
	{"r14", 1},
	{"r13", 2},
	{"r12", 3},
	{"rbp", 4},
	{"rbx", 5},
	{"r11", 6},
	{"r10", 7},
	{"r9", 8},
	{"r8", 9},
	{"rax", 10},
	{"rcx", 11},
	{"rdx", 12},
	{"rsi", 13},
	{"rdi", 14},
	{"orig_rax", 15},
	{"rip", 16},
	{"cs", 17},
	{"eflags", 18},
	{"rsp", 19},
	{"ss", 20},
	{"fs_base", 21},
	{"gs_base", 22},
	{"ds", 23},
	{"es", 24},
	{"fs", 25},
	{"gs", 26}
};

map<SDB::state, string> SDB::state_map = {
	{state::ANY, "ANY"},
	{state::LOADED, "LOADING"},
	{state::RUNNING, "RUNNING"}
};

void SDB::init(){
	current = state::ANY;
	elf_init();
	cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handler);
	eh = nullptr;
	tab = nullptr;
	cpid = 0;
	text_idx = -1;
	bp_idx = -1;
	base_addr = -1;
	last_addr = -1;
	last_disasm = -1;
	last_dump = -1;
	return;
}

void SDB::load_program(vector<string> argv){
	if(current != state::ANY){
		cerr << "** Program: " << program << " has already been loaded. **" << endl;
		cerr << "** " << program 
			<< ": entry point 0x" << hex << eh->entrypoint
			<< ", vaddr 0x" << eh->shdr[text_idx].addr
			<< ", offset 0x" << eh->shdr[text_idx].offset
			<< ", size 0x" << eh->shdr[text_idx].size << endl;
	}
	else if(argv.size() == 1)
        cerr << "** Filename is not specified." << endl;
	else if((eh = elf_open(argv[1].c_str())) == nullptr)
		cerr << "** Unable to open file." << endl;
	else{
		program = argv[1];
		if(elf_load_all(eh) < 0){
            cerr << "** Unable to load ELF file." << endl;
			elf_close(eh);
        	eh = nullptr;
		}
		else{
			for(tab = eh->strtab ; tab != nullptr ; tab = tab->next)
				if(tab->id == eh->shstrndx) break;
			if (tab == nullptr)
                cerr << "** Section header string table is not found." << endl;
			else{
				for(int i=0 ; i<eh->shnum ; ++i){
					if(strcmp(&tab->data[eh->shdr[i].name], ".text") == 0){
						text_idx = i;
						break;
					}
				}
				if (text_idx == -1)
                    cerr << "** .text section is not found." << endl;
				else{
					cerr << "** Program '" << program << "' loaded. "
							<< "entry point 0x" << hex << eh->entrypoint
							<< ", vaddr 0x" << eh->shdr[text_idx].addr
							<< ", offset 0x" << eh->shdr[text_idx].offset
							<< ", size 0x" << eh->shdr[text_idx].size << endl;
					current = state::LOADED;
				}
			}
			return;
		}
	}
	return;
}

void SDB::run(){
    string input;
	vector<string> argv;

	cerr << " [" <<  state_map[current] << "] sdb> ";
	while(true){
		getline(cin, input);
		argv = split(input);
		if(func_map.find(argv[0]) != func_map.end()){
			if(func_map[argv[0]] == &SDB::quit)
				break;
			(this->*func_map[argv[0]])(argv);
		}
		else
			cerr << "** Command not found." << endl;
		cerr << " [" <<  state_map[current] << "] sdb> ";
	}
    return;
}

void SDB::exec(vector<string> argv){
	exec_impl(argv, true);
	return;
}

void SDB::start_exec(vector<string> argv){
	exec_impl(argv, false);
	return;
}

void SDB::continue_exec(vector<string> argv){
	continue_impl(argv, PTRACE_CONT);
	return;
}

void SDB::run_a_instruction(vector<string> argv){
	continue_impl(argv, PTRACE_SINGLESTEP);
	return;
}

void SDB::exec_impl(vector<string> argv, bool conti){
	if(current == state::ANY)
		cerr << "** Must load file first." << endl;
	else if(current == state::RUNNING)
		cerr << "** Already in the running state." << endl;
	else{
		if((cpid = fork()) < 0)
			cerr << "** Fail to create child process." << endl;
		else{
			if(cpid == 0){
				if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
					cerr << "** Ptrace Failed" << endl;
				
				char* args[256] = {nullptr};
				for (size_t i = 1; i < argv.size(); ++i)
                    args[i-1] = strdup(argv[i].c_str());
				
				char cwd[256];
                getcwd(cwd, sizeof(cwd));
				strcat(cwd, "/");
				strcat(cwd, program.c_str());
				execvp(cwd, args);
			}
			else{
				int status;
				waitpid(cpid, &status, 0);
				
				ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_EXITKILL);
				get_base_address();

				if (base_addr + eh->shdr[text_idx].offset == eh->shdr[text_idx].addr)
                    base_addr = 0;

				long ret;
                for (auto& item : breakpoints)
                {
                    item.addr += base_addr;
                    ret = ptrace(PTRACE_PEEKTEXT, cpid, item.addr, 0);
                    if (ptrace(PTRACE_POKETEXT, cpid, item.addr, (ret & ~0xff) | 0xcc) != 0)
                        cerr << "ptrace(POKETEXT)" << endl;
                }
				if(last_disasm != -1)
					base_addr += last_disasm;

				cerr << "** Pid: " << dec << cpid << endl;
				current = state::RUNNING;
			}
		}	
	}
	
	if(conti)
		continue_impl(argv, PTRACE_CONT);
	else
		check_bp();
	return;
}

void SDB::continue_impl(vector<string> argv, __ptrace_request command){
	if(current != state::RUNNING)
		cerr << "** Must be in the RUNNING state." << endl;
	else{
		long ret;
		if(bp_idx != -1){
			ret = ptrace(PTRACE_PEEKTEXT, cpid, breakpoints[bp_idx].addr, 0);
			ret = (ret & ~0xff) | breakpoints[bp_idx].orig_byte;
			if (ptrace(PTRACE_POKETEXT, cpid, breakpoints[bp_idx].addr, ret) != 0)
				perror("ptrace(POKETEXT)");
			if (ptrace(PTRACE_SETREGS, cpid, 0, &regs) != 0)
				perror("ptrace(SETREGS)");
		}
		ptrace(command, cpid, 0, 0);
		if(bp_idx != -1){
			ret = (ret & ~0xff) | (0x000000ff & 0xcc);
			if (ptrace(PTRACE_POKETEXT, cpid, breakpoints[bp_idx].addr, ret) != 0 && errno != 3)
				perror("ptrace(POKETEXT)");
		}

		int status;
		if(waitpid(cpid, &status, 0) < 0)
			cerr << "[Error] --> continue_impl (waitpid)" << endl;
		if(!WIFSTOPPED(status))
			program_termination(status);
		else
			check_bp();
		return;
	}
	return;
}

void SDB::quit(vector<string> argv){
	int status;
	if(waitpid(cpid, &status, 0) < 0)
		cerr << "[Error] --> quit (waitpid)" << endl;
	if(!WIFSTOPPED(status))
		program_termination(status);
    else
        check_bp();
	return;
}

void SDB::get_reg(vector<string> argv){
	if(current != state::RUNNING)
		cerr << "** Must be in the RUNNING state." << endl;
	else{
		if(reg_map.find(argv[1]) == reg_map.end())
			cerr << "** Register: '" << argv[1] << "' is not found." << endl;
		else{
			unsigned long long int *reg_ptr = reinterpret_cast<unsigned long long int*>(&regs);
			cerr << argv[1] << " = " << dec << *(reg_ptr + reg_map[argv[1]]) << hex << " (0x" << *(reg_ptr + reg_map[argv[1]]) << ")" << endl;
		}
	}
	return;
}

void SDB::get_all_reg(vector<string> argv){
	if(current != state::RUNNING)
		cerr << "** Must be in the RUNNING state." << endl;
	else{
		unsigned long long int *reg_ptr = reinterpret_cast<unsigned long long int*>(&regs);
		for(auto& reg : reg_map){
			cerr << reg.first << " = " << dec << *(reg_ptr + reg.second) << hex << " (0x" << *(reg_ptr + reg.second) << ")" << endl;
		}
	}
	return;
}

void SDB::set_reg(vector<string> argv){
	if(current != state::RUNNING)
		cerr << "** Must be in the RUNNING state." << endl;
	else{
		if (reg_map.find(argv[1]) == reg_map.end())
            cerr << "** Register is not found." << endl;
		else
		{
			unsigned long long int *reg_ptr = reinterpret_cast<unsigned long long int*>(&regs);
			*(reg_ptr + reg_map[argv[1]]) = stoull(argv[2], nullptr, 0);
			if (ptrace(PTRACE_SETREGS, cpid, 0, &regs) != 0)
				perror("ptrace(SETREGS)");
		}
		if (argv[1] == "rip")
			check_bp();
	}
}

void SDB::set_bp(vector<string> argv){
	long long addr = stoll(argv[1], nullptr, 0);
	for(auto& bp : breakpoints){
		if(bp.addr == addr){
			cerr << "Break point is already set." << endl;
			return;
		}
	}
	if(current == state::ANY)
		cerr << "Must be in the LOADED or the RUNNING state." << endl;
	else if(current == state::LOADED){
		if(addr < eh->shdr[text_idx].addr || addr >= eh->shdr[text_idx].addr + eh->shdr[text_idx].size)
			cerr << "Address out of range." << endl;
		else{
			bp_t tmp;
			tmp.addr = addr;
			lseek(eh->fd, eh->shdr[text_idx].offset + addr - eh->shdr[text_idx].addr, SEEK_SET);
			read(eh->fd, &tmp.orig_byte, sizeof(tmp.orig_byte));
			breakpoints.push_back(tmp);
		}
	}
	else if(current == state::RUNNING){
		if(addr < eh->shdr[text_idx].addr + base_addr || addr >= last_addr)
			cerr << "Address out of range." << endl;
		else{
			bp_t tmp;
			tmp.addr = addr;
			long ret = ptrace(PTRACE_PEEKTEXT, cpid, addr, 0);
			memcpy(&tmp.orig_byte, &ret, 1);
			breakpoints.push_back(tmp);
			if (ptrace(PTRACE_POKETEXT, cpid, addr, (ret & ~0xff) | 0xcc) != 0)
				cerr << "ptrace(POKETEXT)" << endl;
		}
	}
	else;
	return;
}

void SDB::del_bp(vector<string> argv){
	unsigned long idx = stoul(argv[1]);
	if (idx < 0 || idx >= breakpoints.size())
		cerr << "** Break point not found." << endl;
	else{
		if(current == state::RUNNING)
		{
			long ret = ptrace(PTRACE_PEEKTEXT, cpid, breakpoints[idx].addr, 0);
			ret = (ret & ~0xff) | breakpoints[idx].orig_byte;
			if (ptrace(PTRACE_POKETEXT, cpid, breakpoints[idx].addr, ret) != 0)
				cerr << "ptrace(POKETEXT)" << endl;
			if (bp_idx == (int)idx)
			{
				bp_idx = -1;
				if (ptrace(PTRACE_SETREGS, cpid, 0, &regs) != 0)
					perror("ptrace(SETREGS)");
			}
		}
		breakpoints.erase(breakpoints.begin() + idx);
		cerr << "** Breakpoint " << idx << " is deleted." << endl;
	}
	return;
}

void SDB::list_bp(vector<string> argv){
	for (size_t i = 0; i < breakpoints.size(); ++i){
		cerr << dec << right << setw(2) << i << 
			<< hex << setw(16) << breakpoints[i].addr << " " << endl;
	}
    return;
}

void SDB::check_bp(){
	if(ptrace(PTRACE_GETREGS, cpid, 0, &regs) != 0)
    	cerr << "ptrace(GETREGS)" << endl;
	
	for(size_t i=0 ; i<breakpoints.size(); ++i){
		if (breakpoints[i].addr == (long long) regs.rip-1){
			bp_idx = i;
			break;
		}
	}

	if(bp_idx != -1){
		unsigned char code[17];
		cs_insn *insn;
		regs.rip -= 1;

		long word;
		for (int i = 0; i < 2; ++i){
			word = ptrace(PTRACE_PEEKTEXT, cpid, regs.rip + i * 8, 0);
			memcpy(code + i * 8, &word, 8);
		}
		code[0] = breakpoints[bp_idx].orig_byte;
		
		if (cs_disasm(capstone_handler, code, sizeof(code) - 1, regs.rip, 1, &insn) == 1)
		{
			cerr << "** Breakpoint @ ";
			print_ins(insn[0]);
			cs_free(insn, 1);
		}
		else
			cerr << "** Fail to disassmble address " << regs.rip << "." << endl;
    }
	
	return;
}

void SDB::dis_asm(vector<string> argv){
	if(current == state::ANY)
		cerr << "** Mist be in the LOADED or the RUNNING state." << endl;
	else{
		if(argv.size() == 1 && last_disasm == -1)
            cerr << "** No addr is given" << endl;
		unsigned char code[113] = {0};
		long code_size = 0;
		long long start_addr = argv.size() == 1 ? last_disasm : stoll(argv[1], nullptr, 0);
		long long end_addr;
		if(current == state::LOADED){
			if (start_addr < eh->shdr[text_idx].addr || start_addr >= eh->shdr[text_idx].addr + eh->shdr[text_idx].size){
				start_addr = -1;
				cerr << "** Address out of range." << endl;
			}
			else{
				size_t seek_pos = start_addr + eh->shdr[text_idx].offset - eh->shdr[text_idx].addr;
				lseek(eh->fd, seek_pos, SEEK_SET);
				read(eh->fd, code, sizeof(code) - 1);
				end_addr = eh->shdr[text_idx].addr + eh->shdr[text_idx].size;
			}
		}
		else if(current == state::RUNNING){
			long word;
			for (int i = 0; i < 14; ++i){
				errno = 0;
				word = ptrace(PTRACE_PEEKTEXT, cpid, start_addr + i * 8, 0);
				if (errno != 0){
					if (i == 0)
						cerr << "** Address out of range." << endl;
					break;
				}
				memcpy(code + i * 8, &word, 8);
				code_size += 8;
			}
			for (auto& item : breakpoints)
			{
				if (item.addr >= start_addr && item.addr < start_addr + code_size)
					*(code + item.addr - start_addr) = item.orig_byte;
			}
			end_addr = start_addr + code_size;
		}
		else;

		if(start_addr != -1){
			size_t count;
			cs_insn *insn;
			count = cs_disasm(capstone_handler, code, sizeof(code) - 1, start_addr, 10, &insn);
			if (count > 0)
			{
				for (size_t i = 0; i < count && start_addr < end_addr; ++i)
				{
					print_ins(insn[i]);
					start_addr += insn[i].size;
				}
				cs_free(insn, count);
			}
			else
				cerr << "** Fail to disassmble address " << start_addr << "." << endl;
			last_disasm = start_addr;
		}
	}
	return;
}

void SDB::print_ins(cs_insn insn){
	int i;
	cerr << hex << right << setw(16) << insn.address << ": " << setfill('0');
	for (i = 0; i < insn.size; ++i)
		cerr << setw(2) << (int)insn.bytes[i] << " ";
	for (; i < 10; ++i)
		cerr << "   ";
	cerr << " " << setfill(' ') << left << setw(6) << insn.mnemonic << " " << insn.op_str << endl;
	return;
}

void SDB::print_mem_layout(vector<string> argv){
	if (current == state::ANY)
        cerr << "** Program is not loaded." << endl;
	else if (current == state::LOADED){
		cerr << setfill('0') << hex << right << setw(16) << eh->shdr[text_idx].addr << "-"
				<< setw(16) << eh->shdr[text_idx].addr + eh->shdr[text_idx].size << " r-x "
				<< setfill(' ') << left << setw(8) << eh->shdr[text_idx].offset << " "
				<< program << endl;
	}
	else if (current == state::RUNNING)
		get_maps();
	else;
	return;
}

void SDB::dump_mem(vector<string> argv){
	if(current == state::ANY)
		cerr << "** Must be in the LOADED or the RUNNING state." << endl;
	else{
		if (argv.size() == 1 && last_dump == -1)
            cerr << "** No addr is given" << endl;
		else{
			long data = -1;
            unsigned char *data_ptr = reinterpret_cast<unsigned char*>(&data);
            string show;
            long long start_addr = argv.size() == 1 ? last_dump : stoll(argv[1], nullptr, 0);
			for (int i = 0; i < 10; ++i){
				errno = 0;
				data = ptrace(PTRACE_PEEKTEXT, cpid, start_addr, 0);
				if (i % 2 == 0){
					if (errno != 0){
						if (i == 0)
							cerr << "** Address out of range." << endl;
						break;
					}
					cerr << right << hex << setfill(' ') << setw(16) << start_addr << ": " << setfill('0');
				}
                    
				for (int j = 0; j < 8; ++j){
					if (errno == 0){
						cerr << setw(2) << (int)*(data_ptr + j) << " ";
						if (*(data_ptr + j) < 32 || *(data_ptr + j) > 126)
							show.push_back('.');
						else
							show.push_back(*(data_ptr + j));
					}
					else{
						cerr << "   ";
						show.push_back(' ');
					}
				}

				if (i % 2 == 1){
                    cerr << " |" << show << "|" << endl;
                    show.clear();
                }
                start_addr += 8;
            }
            cerr << setfill(' ');
            last_dump = start_addr;
		}
	}
	return;
}

void SDB::print_help(vector<string> argv){
	cerr << "- break {instruction-address}: add a break point" << endl;
    cerr << "- cont: continue execution" << endl;
    cerr << "- delete {break-point-id}: remove a break point" << endl;
    cerr << "- disasm addr: disassemble instructions in a file or a memory region" << endl;
    cerr << "- dump addr [length]: dump memory content" << endl;
    cerr << "- exit: terminate the debugger" << endl;
    cerr << "- get reg: get a single value from a register" << endl;
    cerr << "- getregs: show registers" << endl;
    cerr << "- help: show this message" << endl;
    cerr << "- list: list break points" << endl;
    cerr << "- load {path/to/a/program}: load a program" << endl;
    cerr << "- run: run the program" << endl;
    cerr << "- vmmap: show memory layout" << endl;
    cerr << "- set reg val: get a single value to a register" << endl;
    cerr << "- si: step into instruction" << endl;
    cerr << "- start: start the program and stop at the first instruction" << endl;
	return;
}

int main(int argc, char *argv[]){
    SDB* sdb;
	if(argc < 2)
		sdb = new SDB();
    else
		sdb = new SDB(argv[1]);
	sdb->run();
	delete sdb;
    return 0;
}
