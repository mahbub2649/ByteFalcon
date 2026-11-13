// cleaner.cpp: deletion that can't be tricked into deleting the wrong thing.
//  - System folders, the home folder and its top-level standard folders are refused.
//  - The entry is re-checked against the scan (type, and size + mtime for files).
//  - Recursive delete works relative to open directory fds with O_NOFOLLOW, so a symlink
//    swapped in mid-delete can't redirect it, and it never enters another filesystem.
//  - Trash follows the freedesktop.org spec, so files can be restored from the file manager.
#include "cleaner.hpp"
#include <cerrno>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ds {
namespace {

bool under(const std::string &path, const std::string &dir) {
    return path == dir || (path.size() > dir.size() && path.compare(0, dir.size(), dir) == 0 && path[dir.size()] == '/');
}

// Returns 0 or the first errno; `freed` counts what was actually removed.
int removeAt(int dirfd, const char *name, dev_t dev, uint64_t &freed) {
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) return errno;
    if (st.st_dev != dev) return EXDEV;  // a mount point inside: leave it alone
    if (!S_ISDIR(st.st_mode)) {
        if (unlinkat(dirfd, name, 0) != 0) return errno;
        freed += (uint64_t)st.st_blocks * 512;
        return 0;
    }
    int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    std::vector<std::string> names;  // read everything first; deleting while iterating can skip entries
    std::vector<char> buf(32 * 1024);  // heap, not stack: this function recurses once per level
    for (ssize_t n; (n = getdents64(fd, buf.data(), buf.size())) > 0;) {
        for (ssize_t off = 0; off < n;) {
            auto *e = reinterpret_cast<struct dirent64 *>(buf.data() + off);
            off += e->d_reclen;
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) names.emplace_back(e->d_name);
        }
    }
    int firstErr = 0;
    for (auto &n : names) {
        int e = removeAt(fd, n.c_str(), dev, freed);
        if (e && !firstErr) firstErr = e;
    }
    close(fd);
    if (unlinkat(dirfd, name, AT_REMOVEDIR) != 0) return firstErr ? firstErr : errno;
    freed += (uint64_t)st.st_blocks * 512;
    return firstErr;
}

std::string trashDir(const std::string &home) {
    const char *x = getenv("XDG_DATA_HOME");
    return (x && *x ? std::string(x) : home + "/.local/share") + "/Trash";
}

std::string percentEncode(const std::string &p) {
    static const char *hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : p) {
        if (isalnum(c) || c == '/' || c == '-' || c == '_' || c == '.' || c == '~') out += (char)c;
        else { out += '%'; out += hex[c >> 4]; out += hex[c & 15]; }
    }
    return out;
}

std::string moveToTrash(const std::string &path, const std::string &home) {
    std::string td = trashDir(home), files = td + "/files", info = td + "/info";
    for (const std::string &d : {home + "/.local", home + "/.local/share", td, files, info}) mkdir(d.c_str(), 0700);
    std::string base = path.substr(path.rfind('/') + 1), name, infoPath;
    int fd = -1;
    for (int i = 1; fd < 0 && i < 10000; i++) {
        name = i == 1 ? base : base + "." + std::to_string(i);
        infoPath = info + "/" + name + ".trashinfo";
        fd = open(infoPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 && errno != EEXIST) return std::string("cannot write to the Trash: ") + strerror(errno);
    }
    if (fd < 0) return "cannot find a free name in the Trash";
    char date[32];
    time_t now = time(nullptr);
    strftime(date, sizeof date, "%Y-%m-%dT%H:%M:%S", localtime(&now));
    std::string body = "[Trash Info]\nPath=" + percentEncode(path) + "\nDeletionDate=" + date + "\n";
    bool wrote = write(fd, body.data(), body.size()) == (ssize_t)body.size();
    close(fd);
    if (!wrote || rename(path.c_str(), (files + "/" + name).c_str()) != 0) {
        int e = errno;
        unlink(infoPath.c_str());
        if (e == EXDEV) return "it's on a different drive than your Trash; use Delete instead";
        return strerror(e);
    }
    return "";
}

} // namespace

std::string protectedReason(const std::string &path, const std::string &home, const std::string &scanRoot) {
    if (path.empty() || path[0] != '/') return "not an absolute path";
    if (path == "/" || path == home || path == scanRoot) return "refusing to delete a top-level folder";
    if (path.find('/', 1) == std::string::npos) return "refusing to delete a top-level system folder";
    static const char *kSystem[] = {"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
                                    "/run", "/sbin", "/sys", "/usr", "/var/lib", "/snap", "/efi"};
    for (const char *s : kSystem)
        if (under(path, s)) return std::string("system folder (") + s + ")";
    static const char *kHomeKeep[] = {"/.config", "/.local", "/.local/share", "/.ssh", "/.gnupg", "/.mozilla", "/snap",
                                      "/Desktop", "/Documents", "/Downloads", "/Music", "/Pictures", "/Videos",
                                      "/.local/share/Trash", "/.local/share/Trash/files", "/.local/share/Trash/info"};
    for (const char *k : kHomeKeep)
        if (path == home + k) return "important folder; delete what's inside it instead";
    return "";
}

CleanResult cleanEntry(const std::string &path, const Node &rec, bool toTrash, const std::string &home) {
    CleanResult r;
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        r.gone = errno == ENOENT;
        r.error = r.gone ? "already gone" : strerror(errno);
        return r;
    }
    bool typeOk = rec.type == T_DIR ? S_ISDIR(st.st_mode)
                : rec.type == T_FILE ? S_ISREG(st.st_mode)
                : rec.type == T_LINK ? S_ISLNK(st.st_mode)
                                     : !S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode);
    if (!typeOk || (rec.type == T_FILE && ((uint64_t)st.st_size != rec.bytes || st.st_mtime != rec.mtime))) {
        r.error = "changed since the scan; rescan first";
        return r;
    }
    if (toTrash && !under(path, trashDir(home))) {
        r.error = moveToTrash(path, home);
        r.ok = r.error.empty();
        if (r.ok) r.trashed = rec.size;
        return r;
    }
    size_t slash = path.rfind('/');
    std::string parent = slash == 0 ? "/" : path.substr(0, slash), name = path.substr(slash + 1);
    int dfd = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        r.error = strerror(errno);
        return r;
    }
    int e = removeAt(dfd, name.c_str(), st.st_dev, r.freed);
    close(dfd);
    r.ok = e == 0;
    if (!r.ok) r.error = std::string(e == EXDEV ? "contains another mounted drive" : strerror(e)) +
                         (r.freed ? " (partly deleted; rescan to refresh)" : "");
    return r;
}

void detachNode(Tree &t, uint32_t id) {
    Node &n = t.nodes[id];
    uint64_t size = n.size, bytes = n.bytes;
    uint32_t files = n.type == T_DIR ? n.files : (n.type == T_FILE ? 1 : 0);
    if (n.parent != kNone) {
        uint32_t *link = &t.nodes[n.parent].firstChild;
        while (*link != kNone && *link != id) link = &t.nodes[*link].nextSibling;
        if (*link == id) *link = n.nextSibling;
    }
    for (uint32_t a = n.parent; a != kNone; a = t.nodes[a].parent) {
        Node &p = t.nodes[a];
        p.size -= std::min(p.size, size);
        p.bytes -= std::min(p.bytes, bytes);
        p.files -= std::min(p.files, files);
    }
    t.files -= std::min<uint64_t>(t.files, files);
    std::vector<uint32_t> stack{id};
    while (!stack.empty()) {
        uint32_t c = stack.back();
        stack.pop_back();
        t.nodes[c].flags |= F_DELETED;
        for (uint32_t k = t.nodes[c].firstChild; k != kNone; k = t.nodes[k].nextSibling) stack.push_back(k);
    }
}

} // namespace ds
