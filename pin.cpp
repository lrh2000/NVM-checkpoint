#include "pin.H"
#include <signal.h>
#include <linux/elf.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <fcntl.h>

struct trace_t
{
  enum {
    CPT,
    MEM_RD,
    MEM_WR,
    EXIT
  } type:2;
  uint64_t addr:62;
  uint64_t time;
};

static_assert(sizeof(trace_t) == 16);

class traces_t
{
  trace_t *begin, *end;
  trace_t *next;
  int fd;
  size_t size;

  static constexpr size_t SIZE_TO_EXTEND = 128 * 1024 * 1024;
  static constexpr size_t NUM_TO_EXTEND = SIZE_TO_EXTEND / sizeof(trace_t);
  static_assert(NUM_TO_EXTEND * sizeof(trace_t) == SIZE_TO_EXTEND);
  static_assert(SIZE_TO_EXTEND % (2 * 1024 * 1024) == 0);

public:
  void init(void);
  void fini(void);

  trace_t &operator()(void);

private:
  void extend(void);
};

static traces_t traces;
static timespec start_time;
static volatile uint64_t alarm_time;
static int (*__vdso_clock_gettime)(clockid_t clock, struct timespec *ts);
static bool logging = false;

static void LookupVdso(void)
{
  auto vdso = (uint8_t *)getauxval(AT_SYSINFO_EHDR);
  auto header = (Elf64_Ehdr *)vdso;
  auto sections = vdso + header->e_shoff;
  auto nr_sections = header->e_shnum;
  auto shsize = header->e_shentsize;

  char *strtab;
  uint8_t *symbols;
  Elf64_Xword symsize;
  Elf64_Xword nr_symbols;

  for (Elf64_Half i = 0;i < nr_sections;++i)
  {
    auto section = (Elf64_Shdr *)(sections + i * shsize);
    if (section->sh_type == SHT_DYNSYM) {
      symbols = vdso + section->sh_offset;
      symsize = section->sh_entsize;
      nr_symbols = section->sh_size / symsize;
      section = (Elf64_Shdr *)(sections + section->sh_link * shsize);
      strtab = (char *)(vdso + section->sh_offset);
      goto found;
    }
  }
  return;

found:
  for (Elf64_Xword i = 0;i < nr_symbols;++i)
  {
    auto symbol = (Elf64_Sym *)(symbols + i * symsize);
    if (strcmp(strtab + symbol->st_name, "__vdso_clock_gettime") == 0)
      __vdso_clock_gettime = (int (*)(clockid_t, timespec *))(vdso + symbol->st_value);
  }
}

inline void traces_t::extend(void)
{
  int ret = ftruncate(fd, size + SIZE_TO_EXTEND);
  assert(ret == 0);

  begin = (trace_t *)mmap(nullptr, SIZE_TO_EXTEND, PROT_READ | PROT_WRITE, MAP_SHARED, fd, size);
  assert(begin != MAP_FAILED);

  size += SIZE_TO_EXTEND;
  end = begin + NUM_TO_EXTEND;
  next = begin;
}

void traces_t::init(void)
{
  fd = open("/tmp/traces.log", O_TRUNC | O_RDWR | O_CREAT, 0644);
  assert(fd > 0);

  size = 0;
  extend();
}

void traces_t::fini(void)
{
  munmap(begin, SIZE_TO_EXTEND);
  close(fd);
}

inline trace_t &traces_t::operator()(void)
{
  if (__builtin_expect(end == next, false)) {
    munmap(begin, SIZE_TO_EXTEND);
    extend();
  }
  return *next++;
}

static inline uint64_t GetDiffTime(void)
{
  timespec curr;
  __vdso_clock_gettime(CLOCK_MONOTONIC, &curr);
  return curr.tv_nsec - start_time.tv_nsec + (curr.tv_sec - start_time.tv_sec) * 1000000000;
}

static void CheckPoint(uintptr_t ip)
{
  logging = true;
  traces() = (trace_t) {trace_t::CPT, ip, GetDiffTime()};
}

static void MemoryRead(uintptr_t addr)
{
  if (logging)
    traces() = (trace_t) {trace_t::MEM_RD, addr, GetDiffTime()};
}

static void MemoryWrite(uintptr_t addr)
{
  if (logging)
    traces() = (trace_t) {trace_t::MEM_WR, addr, GetDiffTime()};
}

static void Instruction(INS ins, void *)
{
  if (INS_Opcode(ins) == XED_ICLASS_UD2) {
    INS_InsertCall(ins, IPOINT_BEFORE,
        (AFUNPTR)CheckPoint, IARG_INST_PTR, IARG_END);

    INS_Delete(ins);
    return;
  }

  uint32_t num = INS_MemoryOperandCount(ins);
  for (uint32_t i = 0;i < num;++i)
  {
    if (INS_MemoryOperandIsRead(ins, i))
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
          (AFUNPTR)MemoryRead, IARG_MEMORYOP_EA, i, IARG_END);
    if (INS_MemoryOperandIsWritten(ins, i))
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
          (AFUNPTR)MemoryWrite, IARG_MEMORYOP_EA, i, IARG_END);
  }
}

static void Fini(int code, void *)
{
  traces() = (trace_t) {trace_t::EXIT, (uint64_t)code, GetDiffTime()};
  traces.fini();

  printf("%lu\n", GetDiffTime());
}

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv)) {
    puts("Invaild options.");
    return 1;
  }
  PIN_InitSymbols();

  INS_AddInstrumentFunction(Instruction, nullptr);
  PIN_AddFiniFunction(Fini, nullptr);

  LookupVdso();
  if (!__vdso_clock_gettime)
    return 1;

  traces.init();
  __vdso_clock_gettime(CLOCK_MONOTONIC, &start_time);
  PIN_StartProgram();
  return 0;
}
