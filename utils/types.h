#ifndef	_TYPES_H_
#define	_TYPES_H_

#include <stdint.h>

typedef uint32_t Elf32_Addr;
typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Off;
typedef int32_t	 Elf32_Sword;
typedef uint32_t Elf32_Word;

typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Half;
typedef int16_t  Elf64_SHalf;
typedef uint64_t Elf64_Off;
typedef int32_t	 Elf64_Sword;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

//
//	ELF Header
//

#define	EI_MAG0			0
#define	EI_MAG1			1
#define	EI_MAG2			2
#define	EI_MAG3			3
#define	EI_CLASS		4
#define	EI_DATA			5
#define	EI_VERSION		6
#define	EI_NIDENT		16

typedef struct elf32_hdr{
	unsigned char	e_ident[EI_NIDENT];	
	Elf32_Half		e_type;				
	Elf32_Half		e_machine;			
	Elf32_Word		e_version;			
	Elf32_Addr		e_entry;			
	Elf32_Off		e_phoff;			
	Elf32_Off		e_shoff;			
	Elf32_Word		e_flags;			
	Elf32_Half		e_ehsize;			
	Elf32_Half		e_phentsize;		
	Elf32_Half		e_phnum;			
	Elf32_Half		e_shentsize;		
	Elf32_Half		e_shnum;			
	Elf32_Half		e_shstrndx;			
} Elf32_Ehdr;

typedef struct elf64_hdr{
    unsigned char   e_ident[EI_NIDENT];
    Elf64_Half      e_type;
    Elf64_Half      e_machine;
    Elf64_Word      e_version;
    Elf64_Addr      e_entry;
    Elf64_Off       e_phoff;
    Elf64_Off       e_shoff;
    Elf64_Word      e_flags;
    Elf64_Half      e_ehsize;
    Elf64_Half      e_phentsize;
    Elf64_Half      e_phnum;
    Elf64_Half      e_shentsize;
    Elf64_Half      e_shnum;
    Elf64_Half      e_shstrndx;
} Elf64_Ehdr;

#define	ELFMAG0		0x7f
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define ELFMAG      "\177ELF"
#define SELFMAG     4

#define	ELFCLASSNONE	0 	// Invalid class
#define	ELFCLASS32		1 	// 32-bit objects
#define	ELFCLASS64		2 	// 64-bit objects

#define	ELFDATANONE		0
#define	ELFDATA2LSB		1
#define	ELFDATA2MSB		2

//e_type
#define	ET_NONE		0
#define	ET_REL		1
#define	ET_EXEC		2
#define	ET_DYN		3
#define	ET_CORE		4
#define	ET_LOPROC	0xff00
#define	ET_HIPROC	0xffff

//e_machine
#define	EM_NONE		0
#define	EM_M32		1
#define	EM_SPARC	2
#define	EM_386		3
#define	EM_68K		4
#define	EM_88K		5
#define	EM_860		7
#define	EM_MIPS		8
#define	EM_X86_64	62	
#define	EM_ARM 		40	
#define EM_AARCH64  183

#define	EM_NONE_MEANING		"No machine"
#define	EM_M32_MEANING		"AT&T WE 32100"
#define	EM_SPARC_MEANING	"SPARC"
#define	EM_386_MEANING		"Intel 80386"
#define	EM_68K_MEANING		"Motorola 68000"
#define	EM_88K_MEANING		"Motorola 88000"
#define	EM_860_MEANING		"Intel 80860"
#define	EM_MIPS_MEANING		"MIPS RS3000"
#define	EM_X86_64_MEANING	"x86_64"	
#define	EM_ARM_MEANING		"ARM"		

//e_version
#define	EV_NONE		0
#define	EV_CURRENT	1

//
//	Section Header Table
//

typedef struct elf32_shdr{
	Elf32_Word		sh_name;
	Elf32_Word		sh_type;
	Elf32_Word		sh_flags;
	Elf32_Addr		sh_addr;
	Elf32_Off		sh_offset;
	Elf32_Word		sh_size;
	Elf32_Word		sh_link;
	Elf32_Word		sh_info;
	Elf32_Word		sh_addralign;
	Elf32_Word		sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr{
	Elf64_Word     sh_name;
	Elf64_Word     sh_type;
	Elf64_Xword    sh_flags;
	Elf64_Addr     sh_addr;
	Elf64_Off      sh_offset;
	Elf64_Xword    sh_size;
	Elf64_Word     sh_link;
	Elf64_Word     sh_info;
	Elf64_Xword    sh_addralign;
	Elf64_Xword    sh_entsize;
} Elf64_Shdr;

//sh_name
#define	STN_UNDEF		0

//sh_type
#define	SHT_NULL		0
#define	SHT_PROGBITS	1
#define	SHT_SYMTAB		2
#define	SHT_STRTAB		3
#define	SHT_RELA		4
#define	SHT_HASH		5
#define	SHT_DYNAMIC		6
#define	SHT_NOTE		7
#define	SHT_NOBITS		8
#define	SHT_REL 		9
#define	SHT_SHLIB		10
#define	SHT_DYNSYM		11
#define SHT_NUM         12
#define	SHT_LOPROC		0x70000000
#define	SHT_HIPROC		0x7fffffff
#define	SHT_LOUSER		0x80000000
#define	SHT_HIUSER		0xffffffff

//sh_flags
#define	SHF_WRITE		0x1
#define	SHF_ALLOC		0x2
#define	SHF_EXECINSTR	0x4
#define	SHF_MASKPROC	0xf0000000

//sym
typedef struct elf32_sym{
	Elf32_Word		st_name;
	Elf32_Addr		st_value;
	Elf32_Word		st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half		st_shndx;
} Elf32_Sym;

typedef struct elf64_sym {
	Elf64_Word      st_name;
	unsigned char   st_info;
	unsigned char   st_other;
	Elf64_Half      st_shndx;
	Elf64_Addr      st_value;
	Elf64_Xword     st_size;
} Elf64_Sym;

//st_info
#define ELF_ST_BIND(x) ((x) >> 4)
#define ELF_ST_TYPE(x) (((unsigned int) x) & 0xf)
#define ELF32_ST_BIND(x) ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x) ELF_ST_TYPE(x)
#define ELF64_ST_BIND(x) ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x) ELF_ST_TYPE(x)

//高4位表示符号作用域
#define	STB_LOCAL		0
#define	STB_GLOBAL		1
#define	STB_WEAK		2
#define	STB_LOPROC		13
#define	STB_HIPROC		15

//低4位表示符号类型
#define	STT_NOTYPE		0
#define	STT_OBJECT		1
#define	STT_FUNC		2
#define	STT_SECTION		3
#define	STT_FILE		4
#define	STT_LOPROC		13
#define	STT_HIPROC		15

//rel
typedef struct elf32_rel{
	Elf32_Addr		r_offset;
	Elf32_Word		r_info;
} Elf32_Rel;

typedef struct elf32_rela{
	Elf32_Addr		r_offset;
	Elf32_Word		r_info;
	Elf32_Sword		r_addend;
} Elf32_Rela;

typedef struct elf64_rel{
    Elf64_Addr      r_offset;
    Elf64_Xword     r_info;
} Elf64_Rel;

typedef struct elf64_rela{
	Elf64_Addr      r_offset;
	Elf64_Xword     r_info;
	Elf64_Sxword    r_addend;
} Elf64_Rela;

//r_info
#define ELF32_R_SYM(x)  ((x) >> 8)    //动态符号表的索引
#define ELF32_R_TYPE(x) ((x) & 0xff)  //调整类型
#define ELF64_R_SYM(i)  ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)

//type
#define	R_386_JMP_SLOT		7
//#include <bits/elf_arm64.h>
//#include <bits/elf_arm.h>

//dynamic section
typedef struct{
    Elf32_Sword d_tag;
    union {
        Elf32_Sword d_val;
        Elf32_Addr  d_ptr;
    } d_un;
} Elf32_Dyn;

typedef struct{
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr  d_ptr;
    } d_un;
} Elf64_Dyn;

//d_tag
#define DT_NULL 0       //常用来表示dynamic节的结束
#define DT_NEEDED 1     //用来保存需要链接的库的名称，DT_STRTAB + 该表中保存的偏移
           
#define DT_PLTGOT 3     //.got (重定位API)保存了got节的rva

#define DT_HASH 4       //保存了哈希表地址

#define DT_STRTAB 5     //保存了字符串表地址，动态符号字符串表
#define DT_STRSZ 10     //字符串表的大小

#define DT_SYMTAB 6     //保存了符号表地址，动态符号表
#define DT_SYMENT 11    //符号表的大小

#define DT_PLTREL 20    //指定重定位表的解析格式

#define DT_REL 17       //.rel.dyn (重定位全局变量)的地址
#define DT_RELSZ 18     //.rel.dyn (重定位全局变量)的大小
#define DT_RELENT 19    //.rel.dyn (重定位全局变量)每一项的大小
    					//重定位表的结构按照Elf32_Rel解析
         
#define DT_RELA 7       //.rel.dyn (重定位全局变量)的地址
#define DT_RELASZ 8     //.rel.dyn (重定位全局变量)的大小
#define DT_RELAENT 9    //.rel.dyn (重定位全局变量)每一项的大小
    					//重定位表的结构按照Elf32_Rela解析
         
#define DT_JMPREL 23    //.rel.plt 在文件中的偏移, 包含了需要重定位的函数信息
#define DT_PLTRELSZ 2   //.rel.plt节的大小

#define DT_INIT 12      //初始化表
#define DT_FINI 13      //反初始化表
#define DT_SONAME 14    //保存了该so的文件名称
#define DT_RPATH 15     //搜索库的搜索目录字符串
#define DT_SYMBOLIC 16

#define DT_DEBUG 21     //是否被调试使用
#define DT_TEXTREL 22   //代码重定位


//
//	Program Header Table
//

typedef struct elf32_phdr{
	Elf32_Word		p_type;
	Elf32_Off		p_offset;
	Elf32_Addr		p_vaddr;
	Elf32_Addr		p_paddr;
	Elf32_Word		p_filesz;
	Elf32_Word		p_memsz;
	Elf32_Word		p_flags;
	Elf32_Word		p_align;
}  Elf32_Phdr;

typedef struct elf64_phdr{
    Elf64_Word      p_type;
    Elf64_Word      p_flags;
    Elf64_Off       p_offset;
    Elf64_Addr      p_vaddr;
    Elf64_Addr      p_paddr;
    Elf64_Xword     p_filesz;
    Elf64_Xword     p_memsz;
    Elf64_Xword     p_align;
} Elf64_Phdr;

//p_type
#define	PT_NULL		0
#define	PT_LOAD		1
#define	PT_DYNAMIC	2
#define	PT_INTERP	3
#define	PT_NOTE		4
#define	PT_SHLIB	5
#define	PT_PHDR		6
#define	PT_LOPROC	0x70000000
#define	PT_HIPROC	0x7fffffff

//p_flags
#define	PF_X		0x1
#define	PF_W		0x2
#define	PF_R		0x4
#define	PF_MASKPROC	0xf0000000

#endif //_TYPES_H_