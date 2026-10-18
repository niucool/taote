// Ported from qiling/loader/loader.py — QlLoader base implementation.
#include "qiling/loader/loader.hpp"

#include <algorithm>

namespace qiling {
namespace loader {

QlLoader::QlLoader(Qiling* ql) : ql_(ql) {}

QlLoader::~QlLoader() = default;

const Image* QlLoader::find_containing_image(std::uint64_t address) const {
    const auto it = std::find_if(images.begin(), images.end(),
                                 [address](const Image& image) { return image.base <= address && address < image.end; });
    return it == images.end() ? nullptr : &*it;
}

const Image* QlLoader::get_image_by_name(std::string_view name, bool casefold) const {
    // basename match, optionally case-insensitive (loader.py get_image_by_name)
    for (const auto& image : images) {
        std::string_view base = image.path;
        if (const auto slash = base.find_last_of("/\\"); slash != std::string_view::npos) {
            base = base.substr(slash + 1);
        }

        if (casefold) {
            std::string a(base);
            std::string b(name);
            std::transform(a.begin(), a.end(), a.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(b.begin(), b.end(), b.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (a == b) {
                return &image;
            }
        } else if (base == name) {
            return &image;
        }
    }

    return nullptr;
}

std::vector<Image> QlLoader::save() const {
    return images;
}

void QlLoader::restore(const std::vector<Image>& saved_state) {
    images = saved_state;
}

}  // namespace loader
}  // namespace qiling
