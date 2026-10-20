// The API replay store (PLAN_PARITY Phase 5.5): a malware run is only
// reproducible if the *answers* its environment gives it are reproducible, and
// registry, file and network answers are the ones that drift between hosts. The
// store records every dispatch as (name, return value, last error) in order and
// re-checks a later run against that recording, so a difference is named as a
// difference in the environment rather than showing up as a mysterious control
// flow divergence.
//
// The format is one tab-separated line per dispatch (`name \t retval \t
// lasterror`), which keeps the store readable with diff(1) - the point is to be
// able to *see* what changed between two runs.
//
// Windows only for now: hook_winapi is the one dispatch point every Windows API
// call goes through.
#ifndef QILING_OS_REPLAY_HPP
#define QILING_OS_REPLAY_HPP

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace qiling {
namespace os {

class QlApiReplay {
public:
    enum class Mode { Off, Record, Replay };

    // open the store in one of the modes; a failure to open leaves the store
    // off (the run continues, only without replay)
    bool open(Mode mode, const std::string& path) {
        mode_ = Mode::Off;
        entries_.clear();
        mismatches_.clear();
        cursor_ = 0;

        if (mode == Mode::Off || path.empty()) {
            return false;
        }

        if (mode == Mode::Record) {
            out_.open(path, std::ios::trunc);
            if (!out_) {
                return false;
            }
        } else {
            std::ifstream in(path);
            if (!in) {
                return false;
            }
            std::string line;
            while (std::getline(in, line)) {
                std::istringstream parts(line);
                Entry entry;
                if (!std::getline(parts, entry.name, '\t')) {
                    continue;
                }
                std::string field;
                std::getline(parts, field, '\t');
                entry.retval = field.empty() ? 0 : std::stoull(field);
                std::getline(parts, field, '\t');
                entry.last_error = field.empty() ? 0 : std::stoi(field);
                entries_.push_back(entry);
            }
        }

        mode_ = mode;
        return true;
    }

    bool active() const noexcept { return mode_ != Mode::Off; }
    bool replaying() const noexcept { return mode_ == Mode::Replay; }

    // write one dispatch to the recording (no-op unless recording)
    void record(const std::string& name, std::uint64_t retval, int last_error) {
        if (mode_ != Mode::Record || !out_) {
            return;
        }
        // flush per dispatch: a recording is replayed by another process (or the
        // same one later), and an unflushed buffer reads back empty
        out_ << name << '\t' << retval << '\t' << last_error << '\n';
        out_.flush();
    }

    // check one dispatch against the recording; a mismatch is kept with the
    // position and both values so the caller can report it
    bool verify(const std::string& name, std::uint64_t retval, int last_error) {
        if (mode_ != Mode::Replay) {
            return true;
        }
        if (cursor_ >= entries_.size()) {
            mismatches_.push_back(std::to_string(cursor_) + ": unrecorded dispatch " + name);
            ++cursor_;
            return false;
        }
        const auto& expected = entries_[cursor_];
        const auto position = cursor_++;
        if (expected.name != name) {
            mismatches_.push_back(std::to_string(position) + ": recorded " + expected.name + ", replayed " + name);
            return false;
        }
        if (expected.retval != retval || expected.last_error != last_error) {
            std::ostringstream text;
            text << position << ": " << name << " recorded (" << expected.retval << ", " << expected.last_error
                 << "), replayed (" << retval << ", " << last_error << ")";
            mismatches_.push_back(text.str());
            return false;
        }
        return true;
    }

    std::size_t recorded() const noexcept { return entries_.size(); }
    std::size_t mismatches() const noexcept { return mismatches_.size(); }
    const std::vector<std::string>& mismatch_log() const noexcept { return mismatches_; }
    // dispatches the recording still holds at the end (a short replay)
    std::size_t remaining() const noexcept {
        return cursor_ < entries_.size() ? entries_.size() - cursor_ : 0;
    }

private:
    struct Entry {
        std::string name;
        std::uint64_t retval = 0;
        int last_error = 0;
    };

    Mode mode_ = Mode::Off;
    std::ofstream out_;
    std::vector<Entry> entries_;
    std::vector<std::string> mismatches_;
    std::size_t cursor_ = 0;
};

}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_REPLAY_HPP
