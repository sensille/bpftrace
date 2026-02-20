#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <cerrno>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/mman.h>
#include <unistd.h>
#ifdef HAVE_LIBLZMA
#include <lzma.h>
#endif

#include "log.h"
#include "symbols/elf_parser.h"
#include "symbols/user.h"
#include "util/system.h"

namespace bpftrace::symbols {

static int add_symbol(const char* symname,
                      uint64_t /*start*/,
                      uint64_t /*size*/,
                      void* payload)
{
  auto* syms = static_cast<std::set<std::string>*>(payload);
  syms->insert(std::string(symname));
  return 0;
}

#ifdef HAVE_LIBLZMA
// Extract symbols from .gnu_debugdata (MiniDebugInfo) if present.
// This section contains an xz-compressed ELF with a minimal .symtab
// that holds symbols not in .dynsym. Common on Fedora/RHEL systems.
static void add_symbols_from_gnu_debugdata(const std::string& path,
                                           struct bcc_symbol_option& opts,
                                           std::set<std::string>& syms)
{
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0)
    return;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    close(fd);
    return;
  }

  Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
  if (!elf) {
    close(fd);
    return;
  }

  // Find .gnu_debugdata section
  Elf_Scn* scn = nullptr;
  GElf_Shdr shdr;
  size_t shstrndx;
  bool found = false;

  if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
    elf_end(elf);
    close(fd);
    return;
  }

  while ((scn = elf_nextscn(elf, scn)) != nullptr) {
    if (!gelf_getshdr(scn, &shdr))
      continue;
    const char* name = elf_strptr(elf, shstrndx, shdr.sh_name);
    if (name && strcmp(name, ".gnu_debugdata") == 0) {
      found = true;
      break;
    }
  }

  if (!found) {
    elf_end(elf);
    close(fd);
    return;
  }

  // Get the compressed section data
  Elf_Data* data = elf_getdata(scn, nullptr);
  if (!data || !data->d_buf || data->d_size == 0) {
    elf_end(elf);
    close(fd);
    return;
  }

  // Decompress with liblzma
  lzma_stream strm = LZMA_STREAM_INIT;
  if (lzma_auto_decoder(&strm, UINT64_MAX, 0) != LZMA_OK) {
    elf_end(elf);
    close(fd);
    return;
  }

  std::vector<uint8_t> decompressed;
  decompressed.resize(data->d_size * 4); // initial estimate

  strm.next_in = static_cast<const uint8_t*>(data->d_buf);
  strm.avail_in = data->d_size;

  lzma_ret ret;
  do {
    strm.next_out = decompressed.data() + strm.total_out;
    strm.avail_out = decompressed.size() - strm.total_out;

    ret = lzma_code(&strm, LZMA_FINISH);

    if (ret == LZMA_OK && strm.avail_out == 0) {
      decompressed.resize(decompressed.size() * 2);
    }
  } while (ret == LZMA_OK);

  if (ret != LZMA_STREAM_END) {
    LOG(V1) << "Failed to decompress .gnu_debugdata in " << path;
    lzma_end(&strm);
    elf_end(elf);
    close(fd);
    return;
  }

  size_t decompressed_size = strm.total_out;
  lzma_end(&strm);
  elf_end(elf);
  close(fd);

  // Write decompressed ELF to a memfd so bcc_elf_foreach_sym can read it
  int memfd = memfd_create("gnu_debugdata", MFD_CLOEXEC);
  if (memfd < 0)
    return;

  size_t written = 0;
  while (written < decompressed_size) {
    ssize_t n = write(memfd,
                      decompressed.data() + written,
                      decompressed_size - written);
    if (n <= 0) {
      close(memfd);
      return;
    }
    written += n;
  }

  // bcc_elf_foreach_sym needs a path, use /proc/self/fd/N
  std::string memfd_path = "/proc/self/fd/" + std::to_string(memfd);
  bcc_elf_foreach_sym(memfd_path.c_str(), add_symbol, &opts, &syms);
  close(memfd);
}
#endif // HAVE_LIBLZMA

Result<> UserInfoImpl::read_probes_for_pid(int pid) const
{
  if (pid_to_paths_.contains(pid))
    return OK();

  auto result = util::get_mapped_paths_for_pid(pid);
  if (!result) {
    return result.takeError();
  }
  for (auto const& path : *result) {
    auto ok = read_probes_for_path(path);
    if (!ok) {
      // Not all paths will have probes, so we just disregard this
      // path and presume that there were no probes present. This is
      // unlike the case where we have explicitly provided a path,
      // where we will propagte the error if there are no probes.
      //
      // Consider a binary that has probes in the main executable,
      // but is linked against a probeless libc (common case).
      continue;
    }
    pid_to_paths_[pid].emplace(path);
  }

  return OK();
}

Result<> UserInfoImpl::read_probes_for_path(const std::string& path) const
{
  if (path_to_symbols_.contains(path)) {
    return OK();
  }

  // Read all symbols.
  auto& syms = path_to_symbols_[path];
  // Workaround: bcc_elf_foreach_sym() can return the same symbol twice if
  // it's also found in debug info (#1138), so a std::set is used here
  // (and in the add_symbol callback) to ensure that each symbol will be
  // unique in the returned string.
  struct bcc_symbol_option symbol_option;
  memset(&symbol_option, 0, sizeof(symbol_option));
  symbol_option.use_debug_file = 1;
  symbol_option.check_debug_file_crc = 1;
  symbol_option.use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC);
  int err = bcc_elf_foreach_sym(
      path.c_str(), add_symbol, &symbol_option, &syms);
  if (err) {
    return make_error<SystemError>("Extract symbols from " + path, err);
  }

#ifdef HAVE_LIBLZMA
  // Also extract symbols from .gnu_debugdata (MiniDebugInfo) if present.
  // libbcc doesn't handle this section, so we decompress it ourselves and
  // let libbcc enumerate the embedded ELF's symbol table.
  add_symbols_from_gnu_debugdata(path, symbol_option, syms);
#endif

  // Now read all USDT probes.
  auto enumerator = make_usdt_probe_enumerator(path);
  if (enumerator) {
    // TODO: This is a bit of a mess. We are opening the binary twice,
    // parsing ELF twice and extracting symbols in two separate code paths.
    // Now that there is a clear standardized API for extracting user probes,
    // we should take some effort to clear this up and have our own ELF parser
    // which extracts both relevant function symbols and USDT notes.
    auto probes_res = enumerator->enumerate_probes();
    if (probes_res) {
      auto& entries = path_to_usdt_[path];
      std::ranges::for_each(*probes_res,
                            [&](struct usdt_probe_entry& usdt_probe) {
                              entries.emplace(usdt_probe);
                            });
    }
  }

  return OK();
}

Result<BinaryFuncMap> UserInfoImpl::func_symbols_for_pid(int pid) const
{
  auto ok = read_probes_for_pid(pid);
  if (!ok) {
    return ok.takeError();
  }

  BinaryFuncMap funcs;
  for (auto const& path : pid_to_paths_[pid]) {
    funcs.emplace(path, path_to_symbols_[path]);
  }
  return funcs;
}

Result<FunctionSet> UserInfoImpl::func_symbols_for_path(
    const std::string& path) const
{
  auto ok = read_probes_for_path(path);
  if (!ok) {
    return ok.takeError();
  }

  return path_to_symbols_[path];
}

Result<BinaryUSDTMap> UserInfoImpl::usdt_probes_for_pid(int pid) const
{
  auto ok = read_probes_for_pid(pid);
  if (!ok) {
    return ok.takeError();
  }

  BinaryUSDTMap probes;
  for (auto const& path : pid_to_paths_[pid]) {
    probes.emplace(path, path_to_usdt_[path]);
  }
  return probes;
}

Result<BinaryUSDTMap> UserInfoImpl::usdt_probes_for_all_pids() const
{
  auto pids = util::get_all_running_pids();
  if (!pids) {
    return pids.takeError();
  }
  for (int pid : *pids) {
    auto ok = usdt_probes_for_pid(pid);
    if (!ok) {
      continue; // Best effort, don't surface this error.
    }
  }
  return path_to_usdt_;
}

Result<USDTSet> UserInfoImpl::usdt_probes_for_path(
    const std::string& path) const
{
  auto ok = read_probes_for_path(path);
  if (!ok) {
    return ok.takeError();
  }

  return path_to_usdt_[path];
}

} // namespace bpftrace::symbols
