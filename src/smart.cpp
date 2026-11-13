// smart.cpp: finds space that is usually safe to reclaim. One depth-first walk; when a
// folder matches a rule it is "claimed" and not descended into, so nothing is counted twice.
#include "smart.hpp"
#include <ctime>
#include <unordered_map>

namespace ds {
namespace {

struct CatDef { const char *id, *title, *safety, *description, *hint; };

const CatDef kCats[] = {
    {"trash", "Trash", "safe", "Files you already deleted. They keep using disk space until the Trash is emptied.", ""},
    {"cache", "Application caches", "safe",
     "~/.cache: data apps keep to start faster. Rebuilt automatically; close apps first for best results.", ""},
    {"appcache", "Browser & Electron app caches", "safe",
     "Web caches of Chrome, VS Code, Slack, WhatsApp and similar apps inside ~/.config. Rebuilt automatically; close the app first.", ""},
    {"pkgcache", "Package manager caches", "safe",
     "Packages kept by npm, Gradle, Conda, Cargo, Go and Maven. Downloaded again only when needed.", ""},
    {"buildcache", "Build caches", "safe",
     "__pycache__, .pytest_cache, .mypy_cache, Rust target/ folders and folders marked with CACHEDIR.TAG. Rebuilt on the next build.", ""},
    {"partial", "Unfinished downloads", "safe", "Leftovers (.crdownload, .part) from interrupted downloads.", ""},
    {"node_modules", "node_modules folders", "review",
     "Installed JavaScript dependencies. Fine to delete for projects you're not working on; `npm install` restores them.", ""},
    {"venv", "Python virtual environments", "review",
     "Folders with a pyvenv.cfg. Recreate with `python -m venv` and `pip install -r requirements.txt`.", ""},
    {"installers", "Installers & archives in Downloads", "review",
     "Packages, disk images and archives you have probably already installed or extracted.", ""},
    {"olddownloads", "Large, old downloads", "review", "Files over 50 MB in Downloads, unchanged for 90+ days.", ""},
    {"logs", "Large logs & crash dumps", "review", "Log files over 20 MB, rotated logs, crash reports and core dumps.", ""},
    {"android", "Android emulators & system images", "review",
     "Virtual devices and SDK system images. Downloadable again from Android Studio's SDK manager.", ""},
    {"docker", "Docker data", "info", "Docker keeps images, containers and build cache here. Don't delete these files directly.",
     "docker system prune -a"},
    {"journal", "System journal", "info", "System logs kept by journald.", "sudo journalctl --vacuum-size=200M"},
    {"apt", "APT package cache", "info", "Downloaded .deb packages.", "sudo apt clean"},
    {"snap", "Snap package revisions", "info", "Snap keeps old revisions of every app.",
     "snap list --all | awk '/disabled/{print $1, $3}' | while read n r; do sudo snap remove \"$n\" --revision=\"$r\"; done"},
};

enum class Claim { Self, Children, Trash };

bool endsWith(const std::string &s, const char *suf) {
    size_t n = strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

std::string lower(const char *s) {
    std::string r(s);
    for (char &c : r) c = (char)tolower((unsigned char)c);
    return r;
}

class Analyzer {
public:
    Analyzer(const Tree &t, const std::string &home) : t_(t), home_(home), now_(time(nullptr)) {
        for (const CatDef &d : kCats) {
            index_[d.id] = cats_.size();
            cats_.push_back({d.id, d.title, d.safety, d.description, d.hint, {}, 0});
        }
        auto H = [&](const char *rel) { return home_ + rel; };
        exact_ = {
            {H("/.local/share/Trash"), {"trash", Claim::Trash}},
            {H("/.cache"), {"cache", Claim::Children}},
            {H("/.npm/_cacache"), {"pkgcache", Claim::Self}},
            {H("/.npm/_logs"), {"logs", Claim::Self}},
            {H("/.gradle/caches"), {"pkgcache", Claim::Self}},
            {H("/.gradle/wrapper/dists"), {"pkgcache", Claim::Self}},
            {H("/.gradle/daemon"), {"pkgcache", Claim::Self}},
            {H("/miniconda3/pkgs"), {"pkgcache", Claim::Self}},
            {H("/anaconda3/pkgs"), {"pkgcache", Claim::Self}},
            {H("/.conda/pkgs"), {"pkgcache", Claim::Self}},
            {H("/.cargo/registry/cache"), {"pkgcache", Claim::Self}},
            {H("/go/pkg/mod/cache"), {"pkgcache", Claim::Self}},
            {H("/.m2/repository"), {"pkgcache", Claim::Self}},
            {H("/.android/cache"), {"cache", Claim::Self}},
            {H("/.android/avd"), {"android", Claim::Children}},
            {H("/Android/Sdk/system-images"), {"android", Claim::Children}},
            {H("/.docker"), {"docker", Claim::Self}},
            {"/var/lib/docker", {"docker", Claim::Self}},
            {"/var/log/journal", {"journal", Claim::Self}},
            {"/var/cache/apt/archives", {"apt", Claim::Self}},
            {"/var/lib/snapd/snaps", {"snap", Claim::Self}},
            {"/var/crash", {"logs", Claim::Children}},
        };
        homeSlash_ = home_ + "/";
        configPrefix_ = home_ + "/.config/";
        downloads_ = home_ + "/Downloads/";
    }

    std::vector<SmartCategory> run() {
        std::string path = t_.rootPath;
        walk(t_.root, path);
        std::vector<SmartCategory> out;
        for (auto &c : cats_) {
            if (c.items.empty()) continue;
            std::sort(c.items.begin(), c.items.end(), [&](uint32_t a, uint32_t b) { return t_.nodes[a].size > t_.nodes[b].size; });
            out.push_back(std::move(c));
        }
        auto rank = [](const std::string &s) { return s == "safe" ? 0 : s == "review" ? 1 : 2; };
        std::stable_sort(out.begin(), out.end(), [&](auto &a, auto &b) {
            return rank(a.safety) != rank(b.safety) ? rank(a.safety) < rank(b.safety) : a.total > b.total;
        });
        return out;
    }

private:
    void add(const char *cat, uint32_t id) {
        SmartCategory &c = cats_[index_[cat]];
        if (t_.nodes[id].size == 0) return;
        c.items.push_back(id);
        c.total += t_.nodes[id].size;
    }
    bool hasChild(uint32_t dir, const char *name) const {
        for (uint32_t c = t_.nodes[dir].firstChild; c != kNone; c = t_.nodes[c].nextSibling)
            if (strcmp(t_.nodes[c].name, name) == 0) return true;
        return false;
    }
    uint32_t child(uint32_t dir, const char *name) const {
        for (uint32_t c = t_.nodes[dir].firstChild; c != kNone; c = t_.nodes[c].nextSibling)
            if (strcmp(t_.nodes[c].name, name) == 0 && !(t_.nodes[c].flags & F_DELETED)) return c;
        return kNone;
    }

    void walk(uint32_t id, std::string &path) {
        const Node &n = t_.nodes[id];
        if (n.type != T_DIR) {
            if (n.type == T_FILE) fileRule(id, path);
            return;
        }
        if (id != t_.root && dirRule(id, path)) return;
        size_t len = path.size();
        t_.forEachChild(id, [&](uint32_t c) {
            if (path.back() != '/') path += '/';
            path += t_.nodes[c].name;
            walk(c, path);
            path.resize(len);
        });
    }

    bool dirRule(uint32_t id, const std::string &path) {
        const Node &n = t_.nodes[id];
        auto it = exact_.find(path);
        if (it != exact_.end()) {
            const char *cat = it->second.first;
            switch (it->second.second) {
            case Claim::Self: add(cat, id); break;
            case Claim::Children: t_.forEachChild(id, [&](uint32_t c) { add(cat, c); }); break;
            case Claim::Trash:
                for (const char *sub : {"files", "info"}) {
                    uint32_t s = child(id, sub);
                    if (s != kNone) t_.forEachChild(s, [&](uint32_t c) { add(cat, c); });
                }
                break;
            }
            return true;
        }
        const char *name = n.name;
        if (strcmp(name, "node_modules") == 0) { add("node_modules", id); return true; }
        static const char *kBuild[] = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".parcel-cache",
                                       ".turbo", ".sass-cache", ".next"};
        for (const char *b : kBuild)
            if (strcmp(name, b) == 0) { add("buildcache", id); return true; }
        if (n.flags & F_CACHEDIR) { add("buildcache", id); return true; }
        if (strcmp(name, "target") == 0 && hasChild(n.parent, "Cargo.toml")) { add("buildcache", id); return true; }
        if ((!strcmp(name, ".venv") || !strcmp(name, "venv") || !strcmp(name, "env")) && hasChild(id, "pyvenv.cfg")) {
            add("venv", id);
            return true;
        }
        if (path.compare(0, configPrefix_.size(), configPrefix_) == 0) {
            static const char *kWebCache[] = {"Cache", "Code Cache", "GPUCache", "CachedData", "CachedExtensionVSIXs",
                                              "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache",
                                              "ShaderCache", "CacheStorage", "ScriptCache"};
            for (const char *c : kWebCache)
                if (strcmp(name, c) == 0) { add("appcache", id); return true; }
        }
        return false;
    }

    void fileRule(uint32_t id, const std::string &path) {
        const Node &n = t_.nodes[id];
        if (path.compare(0, homeSlash_.size(), homeSlash_) != 0) return;  // file rules only inside home
        std::string name = lower(n.name);
        int64_t age = now_ - n.mtime;
        if (endsWith(name, ".crdownload") || endsWith(name, ".part") || endsWith(name, ".partial")) {
            add("partial", id);
            return;
        }
        if (path.compare(0, downloads_.size(), downloads_) == 0) {
            static const char *kInstall[] = {".deb", ".rpm", ".iso", ".img", ".appimage", ".run", ".dmg", ".exe", ".msi",
                                             ".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".xz", ".bz2", ".zst"};
            for (const char *e : kInstall)
                if (endsWith(name, e)) { add("installers", id); return; }
            if (n.size > 50'000'000 && age > 90 * 86400) { add("olddownloads", id); return; }
        }
        bool core = name == "core" || (name.rfind("core.", 0) == 0 && name.size() > 5 &&
                                       name.find_first_not_of("0123456789", 5) == std::string::npos);
        bool rotated = name.find(".log.") != std::string::npos || endsWith(name, ".log.old") ||
                       name == ".xsession-errors.old";
        if (core || rotated || (endsWith(name, ".log") && n.size > 20'000'000)) add("logs", id);
    }

    const Tree &t_;
    std::string home_, homeSlash_, configPrefix_, downloads_;
    int64_t now_;
    std::vector<SmartCategory> cats_;
    std::unordered_map<std::string, size_t> index_;
    std::unordered_map<std::string, std::pair<const char *, Claim>> exact_;
};

} // namespace

std::vector<SmartCategory> analyzeSmart(const Tree &t, const std::string &home) { return Analyzer(t, home).run(); }

} // namespace ds
