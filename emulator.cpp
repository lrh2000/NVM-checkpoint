#include <cstdint>
#include <cassert>
#include <functional>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/*
 * Part1. Page Table
 */

class pgd_t;
class pud_t;
class pmd_t;
class pte_t;

union pgd_entry_t
{
  struct {
    uint64_t p:1;
    uint64_t rw:1;
    uint64_t us:1;
    uint64_t pwt:1;
    uint64_t pcd:1;
    uint64_t a:1;
    uint64_t unused2:6;
    uint64_t addr:40;
    uint64_t unused1:11;
    uint64_t xd:1;
  } data;
  uint64_t raw;

  pgd_entry_t(void)
    :raw(0)
  {}

  operator pud_t*(void)
  {
    return data.p ? (pud_t *)(data.addr << 12) : nullptr;
  }

  pud_t *operator->(void)
  {
    return (pud_t *)*this;
  }

  void create_if_null(void);
};

static_assert(sizeof(pgd_entry_t) == 8);

union pud_entry_t
{
  struct {
    uint64_t p:1;
    uint64_t rw:1;
    uint64_t us:1;
    uint64_t pwt:1;
    uint64_t pcd:1;
    uint64_t a:1;
    uint64_t unused2:6;
    uint64_t addr:40;
    uint64_t unused1:11;
    uint64_t xd:1;
  } data;
  uint64_t raw;

  pud_entry_t(void)
    :raw(0)
  {}

  operator pmd_t*(void)
  {
    return data.p ? (pmd_t *)(data.addr << 12) : nullptr;
  }

  pmd_t *operator->(void)
  {
    return (pmd_t *)*this;
  }

  void create_if_null(void);
};

static_assert(sizeof(pud_entry_t) == 8);

union pmd_entry_t
{
  struct {
    uint64_t p:1;
    uint64_t rw:1;
    uint64_t us:1;
    uint64_t pwt:1;
    uint64_t pcd:1;
    uint64_t a:1;
    uint64_t unused2:6;
    uint64_t addr:40;
    uint64_t unused1:11;
    uint64_t xd:1;
  } data;
  uint64_t raw;

  pmd_entry_t(void)
    :raw(0)
  {}

  operator pte_t*(void)
  {
    return data.p ? (pte_t *)(data.addr << 12) : nullptr;
  }

  pte_t *operator->(void)
  {
    return (pte_t *)*this;
  }

  void create_if_null(void);
};

static_assert(sizeof(pmd_entry_t) == 8);

union pte_entry_t
{
  struct {
    uint64_t p:1;
    uint64_t rw:1;
    uint64_t us:1;
    uint64_t pwt:1;
    uint64_t pcd:1;
    uint64_t a:1;
    uint64_t d:1;
    uint64_t pat:1;
    uint64_t g:1;
    uint64_t unused2:3;
    uint64_t addr:40;
    uint64_t unused1:7; // used by software
    uint64_t protkey:4;
    uint64_t xd:1;
  } data;
  uint64_t raw;

  pte_entry_t(void)
    :raw(0)
  {}

  operator bool(void)
  {
    return data.p;
  }

  void create_if_null(void)
  {
    if (!data.p)
      raw = 7;
  }
};

static_assert(sizeof(pte_entry_t) == 8);

class pgd_t
{
public:
  void access_read(uintptr_t addr);
  bool access_write(uintptr_t addr, pte_entry_t **ppte = nullptr);
  void end_sync(uintptr_t addr);

  void start_sync(const std::function<void(pte_entry_t *pte)> &func);

  pte_entry_t *locate_pte(uintptr_t addr, bool create = false, pgd_entry_t **ppgd = nullptr,
      pud_entry_t **ppud = nullptr, pmd_entry_t **ppmd = nullptr);

  void *operator new(size_t size);
  void operator delete(void *ptr);

  pgd_t(void) {}
  ~pgd_t(void);
private:
  pgd_entry_t m_entry[512];
};

static_assert(sizeof(pgd_t) == 4096);

class pud_t
{
public:
  void start_sync(const std::function<void(pte_entry_t *pte)> &func);

  pte_entry_t *locate_pte(uintptr_t addr, bool create = false,
      pud_entry_t **ppud = nullptr, pmd_entry_t **ppmd = nullptr);

  void *operator new(size_t size);
  void operator delete(void *ptr);

  pud_t(void) {}
  ~pud_t(void);
private:
  pud_entry_t m_entry[512];
};

static_assert(sizeof(pud_t) == 4096);

class pmd_t
{
public:
  void start_sync(const std::function<void(pte_entry_t *pte)> &func);

  pte_entry_t *locate_pte(uintptr_t addr, bool create = false, pmd_entry_t **ppmd = nullptr);

  void *operator new(size_t size);
  void operator delete(void *ptr);

  pmd_t(void) {}
  ~pmd_t(void);
private:
  pmd_entry_t m_entry[512];
};

static_assert(sizeof(pmd_t) == 4096);

class pte_t
{
public:
  void start_sync(const std::function<void(pte_entry_t *pte)> &func);

  pte_entry_t *locate_pte(uintptr_t addr, bool create = false);

  void *operator new(size_t size);
  void operator delete(void *ptr);

  pte_t(void) {}
  ~pte_t(void) {}
private:
  pte_entry_t m_entry[512];
};

static_assert(sizeof(pte_t) == 4096);

inline pte_entry_t *pgd_t::locate_pte(uintptr_t addr, bool create,
    pgd_entry_t **ppgd, pud_entry_t **ppud, pmd_entry_t **ppmd)
{
  auto &entry = m_entry[(addr >> 39) & 0x1ff];
  if (create)
    entry.create_if_null();
  else if (!entry)
    return nullptr;

  if (ppgd)
    *ppgd = &entry;
  return entry->locate_pte(addr, create, ppud, ppmd);
}

inline pte_entry_t *pud_t::locate_pte(uintptr_t addr, bool create,
    pud_entry_t **ppud, pmd_entry_t **ppmd)
{
  auto &entry = m_entry[(addr >> 30) & 0x1ff];
  if (create)
    entry.create_if_null();
  else if (!entry)
    return nullptr;

  if (ppud)
    *ppud = &entry;
  return entry->locate_pte(addr, create, ppmd);
}

inline pte_entry_t *pmd_t::locate_pte(uintptr_t addr, bool create, pmd_entry_t **ppmd)
{
  auto &entry = m_entry[(addr >> 21) & 0x1ff];
  if (create)
    entry.create_if_null();
  else if (!entry)
    return nullptr;

  if (ppmd)
    *ppmd = &entry;
  return entry->locate_pte(addr, create);
}

inline pte_entry_t *pte_t::locate_pte(uintptr_t addr, bool create)
{
  auto &entry = m_entry[(addr >> 12) & 0x1ff];
  if (create)
    entry.create_if_null();
  else if (!entry)
    return nullptr;

  return &entry;
}

inline void pgd_t::access_read(uintptr_t addr)
{
  pgd_entry_t *pgd;
  pud_entry_t *pud;
  pmd_entry_t *pmd;
  pte_entry_t *pte;

  pte = locate_pte(addr, true, &pgd, &pud, &pmd);
  pgd->data.a = pud->data.a = pmd->data.a = pte->data.a = true;
}

inline bool pgd_t::access_write(uintptr_t addr, pte_entry_t **ppte)
{
  pgd_entry_t *pgd;
  pud_entry_t *pud;
  pmd_entry_t *pmd;
  pte_entry_t *pte;

  pte = locate_pte(addr, true, &pgd, &pud, &pmd);
  if (ppte)
    *ppte = pte;

  if (pgd->data.rw && pud->data.rw && pmd->data.rw && pte->data.rw) {
    pgd->data.a = pud->data.a = pmd->data.a = pte->data.a = true;
    pte->data.d = true;
    return true;
  }

  return false;
}

inline void pgd_t::end_sync(uintptr_t addr)
{
  locate_pte(addr)->data.rw = true;
}

inline void *pgd_t::operator new(size_t size)
{
  return aligned_alloc(4096, size);
}

inline void *pud_t::operator new(size_t size)
{
  return aligned_alloc(4096, size);
}

inline void *pmd_t::operator new(size_t size)
{
  return aligned_alloc(4096, size);
}

inline void *pte_t::operator new(size_t size)
{
  return aligned_alloc(4096, size);
}

inline void pgd_t::operator delete(void *ptr)
{
  free(ptr);
}

inline void pud_t::operator delete(void *ptr)
{
  free(ptr);
}

inline void pmd_t::operator delete(void *ptr)
{
  free(ptr);
}

inline void pte_t::operator delete(void *ptr)
{
  free(ptr);
}

inline void pgd_entry_t::create_if_null(void)
{
  if (!data.p) {
    raw = (uint64_t)new pud_t;
    data.p = data.rw = data.us = true;
  }
}

inline void pud_entry_t::create_if_null(void)
{
  if (!data.p) {
    raw = (uint64_t)new pmd_t;
    data.p = data.rw = data.us = true;
  }
}

inline void pmd_entry_t::create_if_null(void)
{
  if (!data.p) {
    raw = (uint64_t)new pte_t;
    data.p = data.rw = data.us = true;
  }
}

void pgd_t::start_sync(const std::function<void(pte_entry_t *)> &func)
{
  for (auto &entry : m_entry)
    if (entry && entry.data.a)
      entry->start_sync(func), entry.data.a = false;
}

void pud_t::start_sync(const std::function<void(pte_entry_t *)> &func)
{
  for (auto &entry : m_entry)
    if (entry && entry.data.a)
      entry->start_sync(func), entry.data.a = false;
}

void pmd_t::start_sync(const std::function<void(pte_entry_t *)> &func)
{
  for (auto &entry : m_entry)
    if (entry && entry.data.a)
      entry->start_sync(func), entry.data.a = false;
}

void pte_t::start_sync(const std::function<void(pte_entry_t *)> &func)
{
  for (auto &entry : m_entry)
    if (entry && entry.data.d)
      func(&entry), entry.data.rw = entry.data.a = entry.data.d = false;
}

pgd_t::~pgd_t(void)
{
  for (auto &entry : m_entry)
    if (entry)
      delete (pud_t *)entry;
}

pud_t::~pud_t(void)
{
  for (auto &entry : m_entry)
    if (entry)
      delete (pmd_t *)entry;
}

pmd_t::~pmd_t(void)
{
  for (auto &entry : m_entry)
    if (entry)
      delete (pte_t *)entry;
}

static pgd_t *pgd = new pgd_t;

/*
 * Part2. Hardware Copy Engine
 */

static constexpr unsigned int PRIORITY_NUM = 8;
static constexpr uint64_t SYNC_DURATION_NS = 80 * 1000;

static std::vector<pte_entry_t *> ce_cmds[PRIORITY_NUM];
static uint64_t ce_time;
static unsigned int curr_priority = ~0u, curr_index;

static void finish_pending_commands(uint64_t time)
{
  ce_time += SYNC_DURATION_NS;
  while (ce_time < time)
  {
    while (~curr_priority && curr_index == ce_cmds[curr_priority].size())
    {
      --curr_priority;
      curr_index = 0;
    }
    if (!~curr_priority)
      break;

    auto pte = ce_cmds[curr_priority][curr_index++];
    if (pte->data.rw == false) {
      // printf("(%lu) CE: Transfered one page (priority %lu)\n", ce_time, pte->data.unused1);

      pte->data.rw = true;
      ce_time += SYNC_DURATION_NS;
    }
  }
  ce_time -= SYNC_DURATION_NS;
}

/*
 * Part3. Trace Processing
 */

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

static uint64_t pause_time;
static uint32_t checkpoint_id;

static void process_checkpoint(const trace_t &trace)
{
  assert(!~curr_priority);

  for (auto &cmds : ce_cmds)
    cmds.clear();
  pgd->start_sync([] (pte_entry_t *pte) {
      assert(pte->data.unused1 < PRIORITY_NUM);
      ce_cmds[pte->data.unused1].push_back(pte);
    });
  curr_priority = PRIORITY_NUM - 1;
  curr_index = 0;
  ce_time = trace.time;

  ++checkpoint_id;
  printf("(%lu) OS: Checkpoint #%u\n", trace.time, checkpoint_id);
}

static inline void adjust_page_priority(unsigned int priority)
{
  assert(priority >= 1);

  for (auto pte : ce_cmds[priority])
    if (!pte->data.d && pte->data.unused1 == priority)
      --pte->data.unused1;
}

static void process_memory_write(const trace_t &trace)
{
  static unsigned int priority_waiting = 0;

  finish_pending_commands(trace.time);
  while (~priority_waiting && priority_waiting != curr_priority)
  {
    if (priority_waiting != PRIORITY_NUM - 1)
      adjust_page_priority(priority_waiting + 1);
    --priority_waiting;
  }

  pte_entry_t *pte;
  bool ok = pgd->access_write(trace.addr, &pte);
  if (ok)
    return;

  pte->data.rw = true;
  pause_time += SYNC_DURATION_NS;
  ok = pgd->access_write(trace.addr);
  assert(ok);

  printf("(%lu) PF: Waiting for %lx (priority %lu)...\n", trace.time, trace.addr, pte->data.unused1);

  priority_waiting = curr_priority;
  for (unsigned int pr = curr_priority + 2;pr < PRIORITY_NUM;++pr)
    adjust_page_priority(pr);
  if (pte->data.unused1 != PRIORITY_NUM - 1)
    ++pte->data.unused1;
}

static void trace_processing(void)
{
  int fd = open("/tmp/traces.log", O_RDONLY);
  assert(fd > 0);

  struct stat info;
  int ret = fstat(fd, &info);
  assert(ret == 0);

  trace_t *traces = (trace_t *)mmap(nullptr, info.st_size, PROT_READ, MAP_SHARED, fd, 0);
  assert(traces != MAP_FAILED);

  for (int i = 0;;++i)
  {
    auto &trace = traces[i];
    switch (trace.type)
    {
    case trace_t::CPT:
      process_checkpoint(trace);
      break;
    case trace_t::MEM_RD:
      pgd->access_read(trace.addr);
      break;
    case trace_t::MEM_WR:
      process_memory_write(trace);
      break;
    case trace_t::EXIT:
      goto out;
    }
  }

out:
  munmap(traces, info.st_size);
  close(fd);
}

int main(void)
{
  trace_processing();

  return 0;
}
